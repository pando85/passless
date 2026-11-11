#!/usr/bin/env bash
# scripts/run-permission-probes.sh — Permission probes for /dev/uhid and hidraw nodes.
# Runs without root and needs no helper binary. Records machine-readable JSON evidence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${TOOL_DIR}/evidence"
mkdir -p "${EVIDENCE_DIR}"

TIMESTAMP=$(date -Iseconds)

echo "=== Permission Probes ==="
echo "timestamp: ${TIMESTAMP}"
echo ""

# Open the node read-write the way a client would; report whether that works.
can_open_rw() {
    local path="$1"
    ( exec 3<>"${path}" ) 2>/dev/null
}

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
        if can_open_rw "${path}"; then
            open_rw="true"
        fi
    else
        error="\"path does not exist\""
    fi

    echo "{\"label\":\"${label}\",\"path\":\"${path}\",\"exists\":${exists},\"readable\":${readable},\"writable\":${writable},\"open_rw\":${open_rw},\"mode\":\"${mode}\",\"owner_uid\":${owner_uid},\"group_gid\":${group_gid},\"error\":${error}}"
}

PROBES=()

echo "--- /dev/uhid ---"
PROBES+=("$(probe_to_json /dev/uhid uhid)")
echo "${PROBES[-1]}"
echo ""

echo "--- hidraw nodes ---"
for f in /dev/hidraw*; do
    [[ -e "$f" ]] || continue
    PROBES+=("$(probe_to_json "$f" "$(basename "$f")")")
    echo "${PROBES[-1]}"
done

PROBES_JSON=$(IFS=,; echo "${PROBES[*]}")
JSON="{\"phase\":\"permission-probes\",\"timestamp\":\"${TIMESTAMP}\",\"probes\":[${PROBES_JSON}]}"

OUTFILE="${EVIDENCE_DIR}/permission-probes-$(date +%Y%m%dT%H%M%S).json"
echo "${JSON}" | python3 -m json.tool > "${OUTFILE}" 2>/dev/null || echo "${JSON}" > "${OUTFILE}"
echo ""
echo "Evidence written to: ${OUTFILE}"
