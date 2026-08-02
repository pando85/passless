#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC2034
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

for _av_lib in "${SCRIPT_DIR}/lib/"*.sh; do
    # shellcheck disable=SC1090
    [[ -f "$_av_lib" ]] && source "$_av_lib"
done
for _av_stage in "${SCRIPT_DIR}/stages/"*.sh; do
    # shellcheck disable=SC1090
    [[ -f "$_av_stage" ]] && source "$_av_stage"
done
unset _av_lib _av_stage

EXIT_SUCCESS=0
# shellcheck disable=SC2034
EXIT_PREFLIGHT_FAILED=1
EXIT_STAGE_FAILED=2
EXIT_INVALID_ARGS=3
EXIT_INCOMPLETE=6

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Gate C: Real-RP MVP validation (opt-in, fail-closed)

Options:
    --run               Run Gate C stage
    --preflight         Check prerequisites only
    --help              Show this help

Required environment variables:
    AV_PASSLESS_BIN             Path to passless binary
    AV_DAEMON_PROFILE           Agent profile name
    AV_DAEMON_RUNTIME_DIR       Daemon runtime directory
    AV_REAL_RP_CREDENTIAL_REF   Credential reference (never printed/stored)

Optional environment variables:
    AV_REAL_RP_URL              Real RP URL (default: https://tea.millaguie.net)
    AV_REAL_RP_TIMEOUT          Driver timeout seconds (default: 60)
    EVIDENCE_BASE_DIR           Evidence base (default: target/agent-validation)
EOF
}

gc_preflight() {
    local all_ok=true

    for tool in node jq curl dbus-monitor; do
        if command -v "$tool" &>/dev/null; then
            av_log_info "Found: $tool"
        else
            av_log_error "Missing: $tool"
            all_ok=false
        fi
    done

    if [[ -z "${AV_PASSLESS_BIN:-}" ]]; then
        av_log_error "AV_PASSLESS_BIN not set"
        all_ok=false
    elif [[ ! -x "${AV_PASSLESS_BIN}" ]] && ! command -v "${AV_PASSLESS_BIN}" &>/dev/null; then
        av_log_error "passless binary not found: ${AV_PASSLESS_BIN}"
        all_ok=false
    fi

    for var in AV_DAEMON_PROFILE AV_DAEMON_RUNTIME_DIR AV_REAL_RP_CREDENTIAL_REF; do
        if [[ -z "${!var:-}" ]]; then
            av_log_error "$var not set"
            all_ok=false
        fi
    done

    if [[ ! -f "${SCRIPT_DIR}/browser/real-rp-driver.js" ]]; then
        av_log_error "real-rp-driver.js not found"
        all_ok=false
    fi

    if [[ "$all_ok" == "true" ]]; then
        av_log_success "Gate C preflight passed"
        return 0
    else
        av_log_error "Gate C preflight failed"
        return 1
    fi
}

gc_run() {
    local start_time
    start_time=$(date -u +%Y%m%d-%H%M%S)
    local run_id
    run_id="${RUN_ID_PREFIX:-gate-c}-${start_time}-$(openssl rand -hex 4 2>/dev/null || date +%s%N)"

    local evidence_base="${EVIDENCE_BASE_DIR:-target/agent-validation}"
    mkdir -p "$evidence_base"
    local evidence_dir="${evidence_base}/${run_id}"
    mkdir -p "$evidence_dir"
    chmod 700 "$evidence_dir"

    export EVIDENCE_DIR="$evidence_dir"
    export TEMP_ROOT="${evidence_dir}/tmp"
    mkdir -p "$TEMP_ROOT"
    chmod 700 "$TEMP_ROOT"

    # shellcheck disable=SC2034
    local log_file="${evidence_dir}/orchestrator.log"

    av_log_info "Gate C run: $run_id"
    av_log_info "Evidence: $evidence_dir"

    stage_real_rp || true

    local report_file="${evidence_dir}/report.json"
    local results_file="${evidence_dir}/real-rp-results.json"

    if [[ -f "$results_file" ]]; then
        cp "$results_file" "$report_file"
    else
        jq -n '{status:"incomplete",reason:"stage did not produce results",gate:"C"}' > "$report_file"
    fi

    local overall_status
    overall_status=$(jq -r '.status // "incomplete"' "$report_file" 2>/dev/null || echo "incomplete")

    {
        echo "# Gate C Real-RP Validation Report"
        echo ""
        echo "- Run ID: $run_id"
        echo "- Status: $overall_status"
        echo "- Gate: C"
        echo ""
        echo '```json'
        jq '.' "$report_file" 2>/dev/null || cat "$report_file"
        echo '```'
    } > "${evidence_dir}/report.md"

    av_log_info "Report: ${evidence_dir}/report.md"

    case "$overall_status" in
        pass) exit $EXIT_SUCCESS ;;
        fail) exit $EXIT_STAGE_FAILED ;;
        incomplete) exit $EXIT_INCOMPLETE ;;
        *) exit $EXIT_INCOMPLETE ;;
    esac
}

main() {
    local mode=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --run) mode="run"; shift ;;
            --preflight) mode="preflight"; shift ;;
            --help|-h) usage; exit $EXIT_SUCCESS ;;
            *) av_log_error "Unknown option: $1"; usage; exit $EXIT_INVALID_ARGS ;;
        esac
    done

    if [[ -z "$mode" ]]; then
        usage
        exit $EXIT_INVALID_ARGS
    fi

    case "$mode" in
        preflight) gc_preflight ;;
        run) gc_run ;;
    esac
}

main "$@"
