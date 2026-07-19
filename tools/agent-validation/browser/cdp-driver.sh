#!/bin/bash
#
# Isolated Chromium CDP driver for Tier 2 validation
# Uses real Node CDP client to invoke register/authenticate against controlled RP
# Inspects actual page result for REGISTER OK/AUTH OK
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

for _av_lib in "${VALIDATION_DIR}/lib/"*.sh; do
    # shellcheck disable=SC1090
    [[ -f "$_av_lib" ]] && source "$_av_lib"
done
unset _av_lib

usage() {
    cat << EOF
Usage: $(basename "$0") <command> [options]

Commands:
    register   Register a passkey against the controlled RP
    authenticate  Authenticate against the controlled RP
    health     Check CDP connection health

Environment variables:
    AV_CDP_PORT          CDP debugging port (default: 9222)
    AV_RP_URL            RP URL (default: http://127.0.0.1:8443)
    AV_EVIDENCE_DIR      Evidence directory for results
EOF
}

cmd_health() {
    local port="${AV_CDP_PORT:-9222}"
    local result
    if result=$(av_cdp_evaluate "true" "$port" 2>&1); then
        if echo "$result" | jq -e '.value == true' &>/dev/null; then
            echo '{"status":"ok","port":"'"$port"'"}'
            return 0
        fi
    fi
    echo '{"status":"error","port":"'"$port"'","error":"CDP not reachable"}'
    return 1
}

cmd_register() {
    local port="${AV_CDP_PORT:-9222}"
    local rp_url="${AV_RP_URL:-http://127.0.0.1:8443}"
    local evidence_dir="${AV_EVIDENCE_DIR:-/tmp}"

    local result_file="${evidence_dir}/cdp-register-result.json"

    av_log_info "Navigating to RP: $rp_url"
    if ! av_cdp_navigate "$rp_url" "$port" 2>/dev/null; then
        jq -n --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --arg status "error" \
            --arg error "navigation_failed" \
            '{timestamp: $timestamp, status: $status, error: $error}' > "$result_file"
        return 1
    fi

    sleep 2

    av_log_info "Invoking register via CDP..."
    local register_expr
    register_expr=$(cat << 'JSEOF'
(async () => {
    try {
        const btn = document.getElementById('btnRegister');
        if (!btn) return JSON.stringify({error: 'Register button not found'});
        btn.click();
        await new Promise(r => setTimeout(r, 8000));
        const log = document.getElementById('log');
        const lines = log ? log.innerText : '';
        const hasOk = lines.includes('REGISTER OK');
        const hasFail = lines.includes('REGISTER FAIL') || lines.includes('Registration error');
        return JSON.stringify({ok: hasOk, failed: hasFail});
    } catch(e) {
        return JSON.stringify({error: 'browser_exception'});
    }
})()
JSEOF
)

    local eval_result
    if ! eval_result=$(av_cdp_evaluate "$register_expr" "$port" 2>&1); then
        jq -n --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --arg status "error" \
            --arg error "evaluate_failed" \
            '{timestamp: $timestamp, status: $status, error: $error}' > "$result_file"
        return 1
    fi

    local page_result
    page_result=$(echo "$eval_result" | jq -r '.value // "{}"' 2>/dev/null || echo "{}")

    local status="unknown"
    if echo "$page_result" | jq -e '.ok == true' &>/dev/null; then
        status="success"
    elif echo "$page_result" | jq -e '.failed == true or .error' &>/dev/null; then
        status="failed"
    fi

    jq -n \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg rp_url "$rp_url" \
        --arg status "$status" \
        '{timestamp: $timestamp, rp_url: $rp_url, status: $status}' > "$result_file"

    if [[ "$status" == "success" ]]; then
        av_log_success "Registration succeeded"
        return 0
    else
        av_log_error "Registration failed"
        return 1
    fi
}

cmd_authenticate() {
    local port="${AV_CDP_PORT:-9222}"
    local rp_url="${AV_RP_URL:-http://127.0.0.1:8443}"
    local evidence_dir="${AV_EVIDENCE_DIR:-/tmp}"

    local result_file="${evidence_dir}/cdp-authenticate-result.json"

    av_log_info "Invoking authenticate via CDP..."
    local auth_expr
    auth_expr=$(cat << 'JSEOF'
(async () => {
    try {
        const btn = document.getElementById('btnAuthenticate');
        if (!btn) return JSON.stringify({error: 'Authenticate button not found'});
        btn.click();
        await new Promise(r => setTimeout(r, 8000));
        const log = document.getElementById('log');
        const lines = log ? log.innerText : '';
        const hasOk = lines.includes('AUTH OK');
        const hasFail = lines.includes('AUTH FAIL') || lines.includes('Authentication error');
        return JSON.stringify({ok: hasOk, failed: hasFail});
    } catch(e) {
        return JSON.stringify({error: 'browser_exception'});
    }
})()
JSEOF
)

    local eval_result
    if ! eval_result=$(av_cdp_evaluate "$auth_expr" "$port" 2>&1); then
        jq -n --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --arg status "error" \
            --arg error "evaluate_failed" \
            '{timestamp: $timestamp, status: $status, error: $error}' > "$result_file"
        return 1
    fi

    local page_result
    page_result=$(echo "$eval_result" | jq -r '.value // "{}"' 2>/dev/null || echo "{}")

    local status="unknown"
    if echo "$page_result" | jq -e '.ok == true' &>/dev/null; then
        status="success"
    elif echo "$page_result" | jq -e '.failed == true or .error' &>/dev/null; then
        status="failed"
    fi

    jq -n \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg rp_url "$rp_url" \
        --arg status "$status" \
        '{timestamp: $timestamp, rp_url: $rp_url, status: $status}' > "$result_file"

    if [[ "$status" == "success" ]]; then
        av_log_success "Authentication succeeded"
        return 0
    else
        av_log_error "Authentication failed"
        return 1
    fi
}

main() {
    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        health) cmd_health ;;
        register) cmd_register ;;
        authenticate) cmd_authenticate ;;
        --help|-h) usage; exit 0 ;;
        *)
            echo "Unknown command: $cmd" >&2
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"
