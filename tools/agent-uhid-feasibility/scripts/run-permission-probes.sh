#!/usr/bin/env bash
# scripts/run-permission-probes.sh — Permission probes for /dev/uhid and hidraw nodes.
# Runs without root. Records machine-readable JSON evidence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${TOOL_DIR}/evidence"
mkdir -p "${EVIDENCE_DIR}"

TIMESTAMP=$(date -Iseconds)

BIN="${CARGO_TARGET_DIR:-${TOOL_DIR}/target}/debug/uhid-feasibility"
if [[ ! -x "${BIN}" ]]; then
    BIN=$(find /dev/shm -name "uhid-feasibility" -type f -executable 2>/dev/null | head -1)
fi

if [[ ! -x "${BIN:-}" ]]; then
    echo "ERROR: uhid-feasibility binary not found" >&2
    exit 1
fi

echo "=== Permission Probes ==="
echo "timestamp: ${TIMESTAMP}"
echo ""

probe_to_json() {
    local path="$1"
    local label="$2"
    local exists="false" readable="false" writable="false" open_rw="false"
    local mode="null" owner_uid="null" group_gid="null" error="null"

    if [[ -e "${path}" ]]; then
        exists="true"
        mode=$(stat -c '%a' "${path}" 2>/dev/null || echo "0")
        owner_uid=$(stat -c '%u' "${path}" 2>/dev/null || echo "-1")
        group_gid=$(stat -c '%g' "${path}" 2>/dev/null || echo "-1")
        [[ -r "${path}" ]] && readable="true"
        [[ -w "${path}" ]] && writable="true"

        local test_out
        test_out=$("${BIN}" perm "${path}" 2>&1) || true
        if echo "${test_out}" | grep -q "open R/W:.*true"; then
            open_rw="true"
        fi
    else
        error="\"path does not exist\""
    fi

    echo "{\"label\":\"${label}\",\"path\":\"${path}\",\"exists\":${exists},\"readable\":${readable},\"writable\":${writable},\"open_rw\":${open_rw},\"mode\":\"${mode}\",\"owner_uid\":${owner_uid},\"group_gid\":${group_gid},\"error\":${error}}"
}

PROBES=()

echo "--- /dev/uhid ---"
"${BIN}" perm 2>&1 || true
PROBES+=("$(probe_to_json /dev/uhid uhid)")
echo ""

echo "--- hidraw nodes ---"
for f in /dev/hidraw*; do
    [[ -e "$f" ]] || continue
    NAME=$(basename "$f")
    "${BIN}" perm "$f" 2>&1 || true
    PROBES+=("$(probe_to_json "$f" "$NAME")")
    echo ""
done

echo "--- /dev/uhid (tool env) ---"
"${BIN}" env 2>&1 || true

PROBES_JSON=$(IFS=,; echo "${PROBES[*]}")
JSON="{\"phase\":\"0-permission-probes\",\"timestamp\":\"${TIMESTAMP}\",\"probes\":[${PROBES_JSON}]}"

OUTFILE="${EVIDENCE_DIR}/permission-probes-$(date +%Y%m%dT%H%M%S).json"
echo "${JSON}" | python3 -m json.tool > "${OUTFILE}" 2>/dev/null || echo "${JSON}" > "${OUTFILE}"
echo ""
echo "Evidence written to: ${OUTFILE}"
