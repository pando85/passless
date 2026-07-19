#!/usr/bin/env bash
# scripts/run-all.sh — Orchestrator for Phase 0 evidence collection.
# Runs all non-privileged checks, then optionally privileged checks.
#
# Usage:
#   ./scripts/run-all.sh              # non-privileged only
#   ./scripts/run-all.sh --with-priv  # include privileged setup/cleanup
#   ./scripts/run-all.sh --cycles N   # override cycle count (default 1000)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

WITH_PRIV=false
CYCLES=1000

while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-priv) WITH_PRIV=true; shift ;;
        --cycles)    CYCLES="$2"; shift 2 ;;
        *)           echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

echo "============================================"
echo "  Phase 0 Evidence Runner"
echo "  $(date -Iseconds)"
echo "============================================"
echo ""

if [[ "${WITH_PRIV}" == "true" ]]; then
    echo "--- Privileged setup ---"
    if [[ $EUID -ne 0 ]]; then
        echo "Re-running setup with sudo..."
        sudo "${SCRIPT_DIR}/../policy/setup.sh"
    else
        "${SCRIPT_DIR}/../policy/setup.sh"
    fi
    echo ""
fi

echo "--- Step 1/5: Policy validation (dry-run) ---"
"${SCRIPT_DIR}/../policy/validate-rules.sh"
echo ""

echo "--- Step 2/5: Rootless dry-run ---"
"${SCRIPT_DIR}/run-rootless-dryrun.sh"
echo ""

echo "--- Step 3/5: Permission probes ---"
"${SCRIPT_DIR}/run-permission-probes.sh"
echo ""

echo "--- Step 4/5: ${CYCLES}-cycle execution ---"
"${SCRIPT_DIR}/run-1000-cycle.sh" "${CYCLES}"
echo ""

echo "--- Step 5/5: Evidence aggregation ---"
"${SCRIPT_DIR}/capture-evidence.sh"
echo ""

if [[ "${WITH_PRIV}" == "true" ]]; then
    echo "--- Privileged cleanup ---"
    if [[ $EUID -ne 0 ]]; then
        sudo "${SCRIPT_DIR}/../policy/cleanup.sh"
    else
        "${SCRIPT_DIR}/../policy/cleanup.sh"
    fi
    echo ""
fi

echo "============================================"
echo "  Phase 0 complete."
echo "  Evidence files in: ${TOOL_DIR}/evidence/"
echo "============================================"
