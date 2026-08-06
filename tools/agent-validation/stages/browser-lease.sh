#!/bin/bash

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_BROWSER_LEASE_LOADED=true

stage_browser_lease() {
    local evidence_dir="${EVIDENCE_DIR:-/tmp}"
    local results_file="${evidence_dir}/browser-lease-results.json"
    local ceremony_file="${evidence_dir}/agent-ceremonies-results.json"

    if [[ ! -f "$ceremony_file" ]] \
        || ! jq -e '.status == "passed" and .same_user.authentication == "approved" \
            and .same_user.second_assertion == "approved"' "$ceremony_file" >/dev/null 2>&1; then
        jq -n '{status:"skipped",reason:"live same-user ceremony evidence unavailable"}' \
            > "$results_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    local tests=(
        agent::browser::tests::test_manager_revoke_active
        agent::browser::tests::test_manager_check_expired
        agent::browser::tests::test_full_lifecycle_browser_exit_then_cleanup
        agent::browser::tests::test_full_lifecycle_principal_exit_daemon_shutdown
        agent::browser::tests::test_race_expire_and_manual_revoke
        agent::browser::tests::test_pid_mismatch_cleanup_quarantines
        agent::browser::tests::test_login_timeout_expires_pending_lease
        agent::browser::tests::test_transport_failure_pending_cleanup
        agent::sign::tests::test_registry_request_budget_is_shared_for_one_bearer
        agent::sign::tests::sign_handler_tests::dynamic_grant_discovers_credential_created_after_approval
    )
    local test_name
    local log_file="${evidence_dir}/browser-lease-tests.log"
    : > "$log_file"

    for test_name in "${tests[@]}"; do
        local one_log="${TEMP_ROOT:-/tmp}/browser-lease-test.log"
        if ! timeout 180s cargo test --all-features -p passless-rs --bin passless \
            "$test_name" -- --exact --test-threads=1 > "$one_log" 2>&1; then
            cat "$one_log" >> "$log_file"
            jq -n --arg test "$test_name" \
                '{status:"failed",failed_test:$test}' > "$results_file"
            rm -f "$one_log"
            return 1
        fi
        cat "$one_log" >> "$log_file"
        if ! grep -q 'test result: ok\. 1 passed; 0 failed' "$one_log"; then
            jq -n --arg test "$test_name" \
                '{status:"failed",failed_test:$test,reason:"named test did not execute exactly once"}' \
                > "$results_file"
            rm -f "$one_log"
            return 1
        fi
        rm -f "$one_log"
    done

    jq -n --argjson count "${#tests[@]}" \
        '{status:"passed",live_bounded_session:true,deterministic_lifecycle_tests:$count}' \
        > "$results_file"
}
