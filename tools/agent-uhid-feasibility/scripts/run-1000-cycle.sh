#!/usr/bin/env bash
# scripts/run-1000-cycle.sh — 1000-cycle create-destroy execution.
# Requires: R/W access to /dev/uhid (fido group membership).
# Records machine-readable JSON evidence with per-cycle timing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${TOOL_DIR}/evidence"
mkdir -p "${EVIDENCE_DIR}"

CYCLE_COUNT="${1:-1000}"
TIMESTAMP=$(date -Iseconds)

BIN="${CARGO_TARGET_DIR:-${TOOL_DIR}/target}/debug/uhid-feasibility"
if [[ ! -x "${BIN}" ]]; then
    BIN=$(find /dev/shm -name "uhid-feasibility" -type f -executable 2>/dev/null | head -1)
fi

if [[ ! -x "${BIN:-}" ]]; then
    echo "ERROR: uhid-feasibility binary not found" >&2
    exit 1
fi

if [[ ! -w /dev/uhid ]]; then
    echo "ERROR: /dev/uhid not writable (need fido group or root)" >&2
    exit 1
fi

echo "=== 1000-Cycle Execution ==="
echo "timestamp: ${TIMESTAMP}"
echo "cycles:    ${CYCLE_COUNT}"
echo "binary:    ${BIN}"
echo ""

START_EPOCH=$(date +%s%N)
CYCLE_OUT=$("${BIN}" cycle "${CYCLE_COUNT}" 2>&1)
END_EPOCH=$(date +%s%N)

echo "${CYCLE_OUT}"
echo ""

ELAPSED_MS=$(( (END_EPOCH - START_EPOCH) / 1000000 ))

OK_COUNT=$(echo "${CYCLE_OUT}" | grep -c ' OK ' || true)
FAIL_COUNT=$(echo "${CYCLE_OUT}" | grep -c ' FAIL ' || true)
SUMMARY_LINE=$(echo "${CYCLE_OUT}" | tail -1)
REPORTED_OK=$(echo "${SUMMARY_LINE}" | grep -oP '\d+' | head -1)
REPORTED_TOTAL=$(echo "${SUMMARY_LINE}" | grep -oP '\d+' | tail -1)

CREATE_TIMES=()
DESTROY_TIMES=()
while IFS= read -r line; do
    if [[ "${line}" =~ \[([0-9]+)\].*create=([0-9]+)ms.*destroy=([0-9]+)ms ]]; then
        CREATE_TIMES+=("${BASH_REMATCH[2]}")
        DESTROY_TIMES+=("${BASH_REMATCH[3]}")
    fi
done <<< "${CYCLE_OUT}"

if [[ ${#CREATE_TIMES[@]} -gt 0 ]]; then
    CREATE_SUM=0
    CREATE_MAX=0
    CREATE_MIN=999999
    for t in "${CREATE_TIMES[@]}"; do
        CREATE_SUM=$((CREATE_SUM + t))
        [[ ${t} -gt ${CREATE_MAX} ]] && CREATE_MAX=${t}
        [[ ${t} -lt ${CREATE_MIN} ]] && CREATE_MIN=${t}
    done
    CREATE_AVG=$((CREATE_SUM / ${#CREATE_TIMES[@]}))
else
    CREATE_AVG=0; CREATE_MIN=0; CREATE_MAX=0
fi

if [[ ${#DESTROY_TIMES[@]} -gt 0 ]]; then
    DESTROY_SUM=0
    DESTROY_MAX=0
    DESTROY_MIN=999999
    for t in "${DESTROY_TIMES[@]}"; do
        DESTROY_SUM=$((DESTROY_SUM + t))
        [[ ${t} -gt ${DESTROY_MAX} ]] && DESTROY_MAX=${t}
        [[ ${t} -lt ${DESTROY_MIN} ]] && DESTROY_MIN=${t}
    done
    DESTROY_AVG=$((DESTROY_SUM / ${#DESTROY_TIMES[@]}))
else
    DESTROY_AVG=0; DESTROY_MIN=0; DESTROY_MAX=0
fi

echo "--- Timing Summary ---"
echo "wall clock:     ${ELAPSED_MS}ms"
echo "create avg/min/max: ${CREATE_AVG}/${CREATE_MIN}/${CREATE_MAX}ms"
echo "destroy avg/min/max: ${DESTROY_AVG}/${DESTROY_MIN}/${DESTROY_MAX}ms"
echo "ok=${OK_COUNT} fail=${FAIL_COUNT}"
echo ""

echo "--- Post-cycle cleanup scan ---"
CLEANUP_OUT=$("${BIN}" cleanup 2>&1) || true
echo "${CLEANUP_OUT}"
LEFTOVER=$(echo "${CLEANUP_OUT}" | grep -c "^  " || true)

JSON=$(cat <<ENDJSON
{
  "phase": "0-1000-cycle",
  "timestamp": "${TIMESTAMP}",
  "requested_cycles": ${CYCLE_COUNT},
  "reported_ok": ${REPORTED_OK:-0},
  "reported_total": ${REPORTED_TOTAL:-0},
  "wall_clock_ms": ${ELAPSED_MS},
  "create_ms": {"avg": ${CREATE_AVG}, "min": ${CREATE_MIN}, "max": ${CREATE_MAX}},
  "destroy_ms": {"avg": ${DESTROY_AVG}, "min": ${DESTROY_MIN}, "max": ${DESTROY_MAX}},
  "leftover_devices": ${LEFTOVER}
}
ENDJSON
)

OUTFILE="${EVIDENCE_DIR}/cycle-1000-$(date +%Y%m%dT%H%M%S).json"
echo "${JSON}" | python3 -m json.tool > "${OUTFILE}" 2>/dev/null || echo "${JSON}" > "${OUTFILE}"
echo ""
echo "Evidence written to: ${OUTFILE}"
