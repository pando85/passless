#!/bin/bash
#
# Tier 3 Stage: Uninstall Rehearsal
#
# Deterministic teardown and rollback verification:
#   1. Pre-authenticate via controlled RP + CDP driver
#   2. Manifest disposable human credential store (local-json format)
#   3. Record agent state (profile/session/delegation)
#   4. Disable profile, revoke grants, shutdown daemon
#   5. Remove only exact state-recorded test udev artifacts
#   6. Restart human authenticator via fixed mechanism
#   7. Post-authenticate via controlled RP + CDP driver
#   8. Compare store manifests (exactly one sign_count increase allowed)
#   9. Verify agent absent, human intact
#
# Required environment variables:
#   AV_UNINSTALL_PASSLESS_BIN        - absolute path to passless binary
#   AV_UNINSTALL_PROFILE_IDS         - comma-separated agent profile IDs
#   AV_UNINSTALL_HUMAN_STORE         - absolute path to disposable human credential store
#   AV_UNINSTALL_STORE_FORMAT        - must be "local-json"
#   AV_UNINSTALL_RP_URL              - controlled RP URL
#   AV_UNINSTALL_RP_PORT             - controlled RP port
#   AV_UNINSTALL_BROWSER_USER        - human browser username
#   AV_UNINSTALL_RESTART_MECHANISM   - enum: systemctl--user, none
#   AV_UNINSTALL_AGENT_RUNTIME_DIR   - agent runtime directory (optional)
#   AV_UNINSTALL_REGISTERED_RESOURCES_FILE - path to state file with registered resources
#   AV_AGENT_ADMIN_USE_SUDO          - set to "1" for sudo mode (optional)
#
# Missing live prerequisites => STAGE_SKIPPED, never pass.
# Dry-run => SKIP.
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_PRIVILEGE_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/privilege.sh"
fi
if [[ -z "${AV_LIB_CREDENTIAL_STORE_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/credential-store.sh"
fi
if [[ -z "${AV_LIB_BROWSER_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/browser.sh"
fi
if [[ -z "${AV_LIB_CONTROLLED_RP_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/controlled-rp.sh"
fi
if [[ -z "${AV_LIB_NOTIFICATIONS_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/notifications.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_UNINSTALL_REHEARSAL_LOADED=true

_av_uninstall_start_approver() {
    (
        while true; do
            local count
            count=$(dunstctl count 2>/dev/null || echo 0)
            if [[ "$count" =~ ^[0-9]+$ && "$count" -gt 0 ]]; then
                sleep "${AV_PROMPT_APPROVAL_DELAY_SECS:-2}"
                dunstctl action 0 >/dev/null 2>&1 || true
            else
                sleep 0.1
            fi
        done
    ) &
    AV_UNINSTALL_APPROVER_PID=$!
}

_av_uninstall_cleanup() {
    if [[ -n "${AV_UNINSTALL_APPROVER_PID:-}" ]] \
        && kill -0 "$AV_UNINSTALL_APPROVER_PID" 2>/dev/null; then
        kill "$AV_UNINSTALL_APPROVER_PID" 2>/dev/null || true
        wait "$AV_UNINSTALL_APPROVER_PID" 2>/dev/null || true
    fi
    av_stop_chromium 2>/dev/null || true
    av_stop_controlled_rp 2>/dev/null || true
}

stage_uninstall_rehearsal() {
    local evidence_dir="${EVIDENCE_DIR:-/tmp}"
    local report_file="${evidence_dir}/uninstall-rehearsal-report.json"
    local violations=0
    local checks_json="[]"

    add_check() {
        local check="$1" name="$2" status="$3" detail="$4"
        checks_json=$(printf '%s' "$checks_json" | jq \
            --arg c "$check" --arg n "$name" --arg s "$status" --arg d "$detail" \
            '. + [{"check": $c, "name": $n, "status": $s, "detail": $d}]')
    }

    local passless_bin="${AV_UNINSTALL_PASSLESS_BIN:-}"
    local profile_ids_csv="${AV_UNINSTALL_PROFILE_IDS:-}"
    local human_store="${AV_UNINSTALL_HUMAN_STORE:-}"
    local store_format="${AV_UNINSTALL_STORE_FORMAT:-}"
    local rp_url="${AV_UNINSTALL_RP_URL:-}"
    local rp_port="${AV_UNINSTALL_RP_PORT:-}"
    local browser_user="${AV_UNINSTALL_BROWSER_USER:-}"
    local restart_mechanism="${AV_UNINSTALL_RESTART_MECHANISM:-}"
    local agent_runtime_dir="${AV_UNINSTALL_AGENT_RUNTIME_DIR:-}"
    local registered_resources_file="${AV_UNINSTALL_REGISTERED_RESOURCES_FILE:-}"
    local shared_runtime_root="${AV_UNINSTALL_SHARED_RUNTIME_ROOT:-}"
    local use_sudo="${AV_AGENT_ADMIN_USE_SUDO:-0}"

    if av_is_dry_run; then
        av_log_info "[DRY-RUN] Static uninstall-rehearsal analysis..."

        local static_violations=0

        if [[ -z "$passless_bin" ]]; then
            av_log_error "[DRY-RUN] AV_UNINSTALL_PASSLESS_BIN not set"
            ((static_violations++)) || true
        elif [[ "$passless_bin" != /* ]]; then
            av_log_error "[DRY-RUN] passless bin must be absolute: $passless_bin"
            ((static_violations++)) || true
        else
            add_check "STATIC-01" "passless_bin_path" "pass" "absolute path"
        fi

        if [[ -z "$profile_ids_csv" ]]; then
            av_log_error "[DRY-RUN] AV_UNINSTALL_PROFILE_IDS not set"
            ((static_violations++)) || true
        else
            add_check "STATIC-02" "profile_ids" "pass" "profile IDs provided"
        fi

        if [[ -z "$human_store" ]]; then
            av_log_error "[DRY-RUN] AV_UNINSTALL_HUMAN_STORE not set"
            ((static_violations++)) || true
        elif [[ "$human_store" != /* ]]; then
            av_log_error "[DRY-RUN] human store must be absolute: $human_store"
            ((static_violations++)) || true
        else
            add_check "STATIC-03" "human_store_path" "pass" "absolute path"
        fi

        if [[ -z "$store_format" ]]; then
            av_log_error "[DRY-RUN] AV_UNINSTALL_STORE_FORMAT not set"
            ((static_violations++)) || true
        elif [[ "$store_format" != "local-json" ]]; then
            av_log_error "[DRY-RUN] unsupported store format: $store_format"
            ((static_violations++)) || true
        else
            add_check "STATIC-04" "store_format" "pass" "local-json"
        fi

        if [[ -z "$restart_mechanism" ]]; then
            av_log_error "[DRY-RUN] AV_UNINSTALL_RESTART_MECHANISM not set"
            ((static_violations++)) || true
        else
            local mech_valid=false
            local m
            for m in "${AV_ALLOWED_RESTART_MECHANISMS[@]}"; do
                if [[ "$restart_mechanism" == "$m" ]]; then
                    mech_valid=true
                    break
                fi
            done
            if [[ "$mech_valid" != true ]]; then
                av_log_error "[DRY-RUN] invalid restart mechanism: $restart_mechanism"
                ((static_violations++)) || true
            else
                add_check "STATIC-05" "restart_mechanism" "pass" "$restart_mechanism"
            fi
        fi

        if [[ -z "$rp_url" ]] || [[ -z "$rp_port" ]]; then
            av_log_error "[DRY-RUN] AV_UNINSTALL_RP_URL or AV_UNINSTALL_RP_PORT not set"
            ((static_violations++)) || true
        else
            add_check "STATIC-06" "controlled_rp" "pass" "url+port provided"
        fi

        if [[ -z "$browser_user" ]]; then
            av_log_error "[DRY-RUN] AV_UNINSTALL_BROWSER_USER not set"
            ((static_violations++)) || true
        else
            add_check "STATIC-07" "browser_user" "pass" "browser user provided"
        fi

        jq -n \
            --arg timestamp "$(av_capture_timestamp)" \
            --arg mode "dry-run" \
            --argjson violations "$static_violations" \
            --argjson checks "$checks_json" \
            '{timestamp: $timestamp, mode: $mode, violations: $violations, checks: $checks}' \
            > "$report_file"

        av_log_info "[DRY-RUN] Static analysis complete (always SKIP in dry-run)"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if [[ -z "$passless_bin" ]] || [[ -z "$profile_ids_csv" ]] || [[ -z "$human_store" ]] || \
       [[ -z "$store_format" ]] || [[ -z "$rp_url" ]] || [[ -z "$rp_port" ]] || \
       [[ -z "$browser_user" ]] || [[ -z "$restart_mechanism" ]] || [[ -z "$agent_runtime_dir" ]] \
       || [[ -z "$registered_resources_file" ]] || [[ -z "$shared_runtime_root" ]]; then
        av_log_error "Missing required env vars for uninstall-rehearsal"
        add_check "PREREQ-00" "env_vars" "skip" "missing required env vars"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if [[ "$store_format" != "local-json" ]]; then
        av_log_error "unsupported store format: $store_format (must be local-json)"
        add_check "PREREQ-01" "store_format" "skip" "unsupported format"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if [[ ! -x "$passless_bin" ]]; then
        av_log_error "passless binary not executable: $passless_bin"
        add_check "PREREQ-02" "passless_bin" "skip" "not executable"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if ! av_validate_absolute_path "$passless_bin" "passless_bin"; then
        add_check "PREREQ-02" "passless_bin_path" "skip" "path validation failed"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    add_check "PREREQ-02" "passless_bin" "pass" "$passless_bin"

    if ! av_validate_absolute_path "$human_store" "human_store"; then
        add_check "PREREQ-03" "human_store_path" "skip" "path validation failed"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if ! av_validate_store_path "$human_store"; then
        av_log_error "human store validation failed: $human_store"
        add_check "PREREQ-03" "human_store" "skip" "store validation failed"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    add_check "PREREQ-03" "human_store" "pass" "$human_store"

    if ! av_chromium_prereqs_check 2>/dev/null; then
        av_log_warn "Chromium/CDP prerequisites not met"
        add_check "PREREQ-04" "chromium_cdp" "skip" "prerequisites not met"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    add_check "PREREQ-04" "chromium_cdp" "pass" "available"

    if ! av_controlled_rp_prereqs_check 2>/dev/null; then
        av_log_warn "Controlled RP prerequisites not met"
        add_check "PREREQ-05" "controlled_rp" "skip" "prerequisites not met"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    add_check "PREREQ-05" "controlled_rp" "pass" "available"

    if ! id "$browser_user" &>/dev/null; then
        av_log_warn "Browser user does not exist: $browser_user"
        add_check "PREREQ-06" "browser_user" "skip" "user does not exist"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    add_check "PREREQ-06" "browser_user" "pass" "$browser_user"

    local profile_ids=()
    IFS=',' read -ra profile_ids <<< "$profile_ids_csv"
    if [[ ${#profile_ids[@]} -lt 2 ]]; then
        add_check "PREREQ-07" "profile_set" "skip" "isolated and delegated profile IDs are required"
        jq -n --argjson checks "$checks_json" \
            '{violations:0,checks:$checks,status:"skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    local profile_id
    for profile_id in "${profile_ids[@]}"; do
        if [[ ! "$profile_id" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$ ]]; then
            add_check "PREREQ-07" "profile_set" "fail" "invalid profile ID"
            return 1
        fi
    done

    if [[ "$shared_runtime_root" != /* || ! -d "$shared_runtime_root" \
        || -L "$shared_runtime_root" || ! -f "$registered_resources_file" \
        || "$agent_runtime_dir" != /* || -L "$agent_runtime_dir" ]]; then
        add_check "PREREQ-07" "runtime_and_state" "skip" "shared runtime root or state file unavailable"
        jq -n --argjson checks "$checks_json" \
            '{violations:0,checks:$checks,status:"skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    if ! command -v dunstctl &>/dev/null \
        || ! dunstctl running 2>/dev/null | grep -Eqi 'true|yes|1|running'; then
        add_check "PREREQ-08" "notification_session" "skip" "daemon and dunst do not share an active session"
        jq -n --argjson checks "$checks_json" \
            '{violations:0,checks:$checks,status:"skipped"}' > "$report_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    av_log_info "=== Phase 1: Pre-teardown human authentication ==="

    local cdp_port="${AV_CDP_PORT:-9310}"
    local browser_data_dir="${shared_runtime_root}/browser-profile-uninstall-${RUN_ID:-manual}"
    mkdir -p "$browser_data_dir"
    if [[ $EUID -eq 0 ]]; then
        chown "$browser_user" "$browser_data_dir"
    else
        sudo -- chown "$browser_user" "$browser_data_dir"
    fi
    chmod 700 "$browser_data_dir"

    export AV_BROWSER_USER="$browser_user"
    _av_uninstall_start_approver
    trap _av_uninstall_cleanup RETURN
    if ! av_start_chromium_headless "$cdp_port" "$browser_data_dir" 2>/dev/null; then
        av_log_error "Failed to start Chromium for pre-auth"
        add_check "PREAUTH-01" "chromium_start" "fail" "Chromium failed to start"
        ((violations++)) || true
    else
        add_check "PREAUTH-01" "chromium_start" "pass" "Chromium started on port $cdp_port"

        if ! av_find_controlled_rp "${AV_VALIDATION_DIR:-}" 2>/dev/null; then
            av_log_error "Controlled RP not found"
            add_check "PREAUTH-02" "rp_locate" "fail" "not found"
            ((violations++)) || true
        elif ! av_start_controlled_rp "$rp_port" "${AV_VALIDATION_DIR:-}" 2>/dev/null; then
            av_log_error "Controlled RP failed to start"
            add_check "PREAUTH-02" "rp_start" "fail" "failed to start"
            ((violations++)) || true
        else
            add_check "PREAUTH-02" "rp_start" "pass" "RP on port $rp_port"

            local cdp_driver="${AV_VALIDATION_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/browser/cdp-driver.sh"
            if [[ -x "$cdp_driver" ]]; then
                if AV_CDP_PORT="$cdp_port" AV_RP_URL="$rp_url" \
                   AV_EVIDENCE_DIR="$evidence_dir" \
                   bash "$cdp_driver" authenticate 2>/dev/null; then
                    local auth_result_file="${evidence_dir}/cdp-authenticate-result.json"
                    if [[ -f "$auth_result_file" ]]; then
                        local auth_status
                        auth_status=$(jq -r '.status' "$auth_result_file" 2>/dev/null || echo "unknown")
                        if [[ "$auth_status" == "success" ]]; then
                            add_check "PREAUTH-03" "pre_auth" "pass" "AUTH OK before teardown"
                        else
                            av_log_error "Pre-teardown human authentication did not return AUTH OK"
                            add_check "PREAUTH-03" "pre_auth" "fail" "status=$auth_status"
                            ((violations++)) || true
                        fi
                    else
                        av_log_error "Authentication result file not found"
                        add_check "PREAUTH-03" "pre_auth" "fail" "result file missing"
                        ((violations++)) || true
                    fi
                else
                    av_log_error "Pre-teardown human authentication failed"
                    add_check "PREAUTH-03" "pre_auth" "fail" "human auth failed"
                    ((violations++)) || true
                fi
            else
                av_log_warn "CDP driver not found: $cdp_driver"
                add_check "PREAUTH-03" "pre_auth" "skip" "CDP driver not found"
            fi
        fi
    fi

    if jq -e 'any(.[]; .status == "fail" or .status == "skip")' \
        <<<"$checks_json" >/dev/null; then
        av_log_error "Pre-authentication failed or skipped; cannot proceed"
        jq -n \
            --arg timestamp "$(av_capture_timestamp)" \
            --arg mode "live" \
            --argjson violations "$violations" \
            --argjson checks "$checks_json" \
            '{timestamp: $timestamp, mode: $mode, violations: $violations, checks: $checks, status: "skipped"}' \
            > "$report_file"
        av_stop_chromium 2>/dev/null || true
        av_stop_controlled_rp 2>/dev/null || true
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    av_log_info "=== Phase 2: Manifest disposable human store ==="

    local pre_manifest="${evidence_dir}/pre-uninstall-manifest.json"
    if ! av_manifest_credential_store "$human_store" "$pre_manifest" "$store_format"; then
        av_log_error "Failed to create pre-uninstall manifest"
        add_check "MANIFEST-01" "pre_manifest" "fail" "manifest creation failed"
        ((violations++)) || true
    else
        add_check "MANIFEST-01" "pre_manifest" "pass" "manifest created"
    fi

    av_log_info "=== Phase 3: Record agent state ==="

    for profile_id in "${profile_ids[@]}"; do
        local agent_state_file="${evidence_dir}/pre-uninstall-agent-state-${profile_id}.json"
        if ! av_record_agent_state "$passless_bin" "$profile_id" "$agent_state_file" "$use_sudo"; then
            add_check "STATE-01" "record_state" "fail" "state recording failed"
            ((violations++)) || true
        else
            add_check "STATE-01" "record_state" "pass" "state recorded for profile"
        fi
    done

    av_log_info "=== Phase 4: Disable profile, revoke grants, shutdown daemon ==="

    for profile_id in "${profile_ids[@]}"; do
        if ! av_disable_agent_profile "$passless_bin" "$profile_id" "$use_sudo"; then
            add_check "TEARDOWN-01" "disable_profile" "fail" "disable failed"
            ((violations++)) || true
        else
            add_check "TEARDOWN-01" "disable_profile" "pass" "profile disabled"
        fi

        local agent_state_file="${evidence_dir}/pre-uninstall-agent-state-${profile_id}.json"
        if [[ ! -f "$agent_state_file" ]] \
            || ! av_revoke_agent_sessions "$passless_bin" "$profile_id" "$agent_state_file" "$use_sudo"; then
            add_check "TEARDOWN-02" "revoke_sessions" "fail" "revocation failures"
            ((violations++)) || true
        else
            add_check "TEARDOWN-02" "revoke_sessions" "pass" "sessions/grants revoked"
        fi
    done

    if ! av_shutdown_agent_daemon "$passless_bin" "$use_sudo"; then
        av_log_warn "Daemon shutdown had issues"
        add_check "TEARDOWN-03" "shutdown_daemon" "fail" "shutdown failed"
        ((violations++)) || true
    else
        add_check "TEARDOWN-03" "shutdown_daemon" "pass" "daemon shutdown"
    fi

    av_log_info "=== Phase 5: Remove test udev artifacts ==="

    if ! av_remove_test_udev_artifacts "$registered_resources_file"; then
        av_log_warn "Test udev artifact removal had issues"
        add_check "CLEANUP-01" "remove_udev" "fail" "removal issues"
        ((violations++)) || true
    else
        add_check "CLEANUP-01" "remove_udev" "pass" "test udev artifacts removed"
    fi

    av_log_info "=== Phase 6: Restart human authenticator ==="

    if ! av_restart_human_authenticator "$restart_mechanism"; then
        av_log_error "Human authenticator restart failed"
        add_check "RESTART-01" "restart_human" "fail" "restart failed"
        ((violations++)) || true
    else
        add_check "RESTART-01" "restart_human" "pass" "restarted via $restart_mechanism"
    fi

    sleep 2

    av_log_info "=== Phase 7: Post-teardown human authentication ==="

    if [[ -n "${AV_CHROMIUM_PID:-}" ]]; then
        local cdp_driver="${AV_VALIDATION_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/browser/cdp-driver.sh"
        if [[ -x "$cdp_driver" ]]; then
            if AV_CDP_PORT="$cdp_port" AV_RP_URL="$rp_url" \
               AV_EVIDENCE_DIR="$evidence_dir" \
               bash "$cdp_driver" authenticate 2>/dev/null; then
                local auth_result_file="${evidence_dir}/cdp-authenticate-result.json"
                if [[ -f "$auth_result_file" ]]; then
                    local auth_status
                    auth_status=$(jq -r '.status' "$auth_result_file" 2>/dev/null || echo "unknown")
                    if [[ "$auth_status" == "success" ]]; then
                        add_check "POSTAUTH-01" "post_auth" "pass" "AUTH OK after teardown"
                    else
                        av_log_error "Post-teardown human authentication did not return AUTH OK"
                        add_check "POSTAUTH-01" "post_auth" "fail" "status=$auth_status"
                        ((violations++)) || true
                    fi
                else
                    av_log_error "Authentication result file not found"
                    add_check "POSTAUTH-01" "post_auth" "fail" "result file missing"
                    ((violations++)) || true
                fi
            else
                av_log_error "Post-teardown human authentication failed"
                add_check "POSTAUTH-01" "post_auth" "fail" "human auth failed after teardown"
                ((violations++)) || true
            fi
        fi
    else
        add_check "POSTAUTH-01" "post_auth" "skip" "no browser session available"
        ((violations++)) || true
    fi

    av_log_info "=== Phase 8: Post-teardown manifest and comparison ==="

    local post_manifest="${evidence_dir}/post-uninstall-manifest.json"
    if ! av_manifest_credential_store "$human_store" "$post_manifest" "$store_format"; then
        av_log_error "Failed to create post-uninstall manifest"
        add_check "MANIFEST-02" "post_manifest" "fail" "manifest creation failed"
        ((violations++)) || true
    else
        add_check "MANIFEST-02" "post_manifest" "pass" "manifest created"

        local comparison_file="${evidence_dir}/store-manifest-comparison.json"

        if ! av_compare_store_manifests "$pre_manifest" "$post_manifest" "$comparison_file"; then
            av_log_error "Store manifest comparison found unexpected changes"
            add_check "COMPARE-01" "manifest_compare" "fail" "unexpected changes"
            ((violations++)) || true
        else
            local compare_status
            compare_status=$(jq -r '.status' "$comparison_file" 2>/dev/null || echo "unknown")
            add_check "COMPARE-01" "manifest_compare" "pass" "status=$compare_status"
        fi
    fi

    av_log_info "=== Phase 9: Verify agent absent, human intact ==="

    for profile_id in "${profile_ids[@]}"; do
        local agent_absent_file="${evidence_dir}/agent-absent-verify-${profile_id}.json"
        if ! av_verify_agent_absent "$passless_bin" "$profile_id" "${agent_runtime_dir:-}" "$agent_absent_file"; then
            add_check "VERIFY-01" "agent_absent" "fail" "agent artifacts remain"
            ((violations++)) || true
        else
            add_check "VERIFY-01" "agent_absent" "pass" "agent artifacts removed"
        fi
    done

    local human_intact_file="${evidence_dir}/human-intact-verify.json"
    if ! av_verify_human_intact "$human_store" "$passless_bin" "$human_intact_file"; then
        av_log_error "Human store/process not intact after teardown"
        add_check "VERIFY-02" "human_intact" "fail" "human compromised"
        ((violations++)) || true
    else
        add_check "VERIFY-02" "human_intact" "pass" "human intact"
    fi

    av_stop_chromium 2>/dev/null || true
    av_stop_controlled_rp 2>/dev/null || true

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --arg mode "live" \
        --argjson violations "$violations" \
        --argjson checks "$checks_json" \
        '{timestamp: $timestamp, mode: $mode, violations: $violations, checks: $checks}' \
        > "$report_file"

    if [[ $violations -gt 0 ]]; then
        av_log_error "Uninstall rehearsal: $violations violation(s) found"
        return 1
    fi

    av_log_success "Uninstall rehearsal: all checks passed"
    return 0
}
