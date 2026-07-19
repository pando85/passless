#!/usr/bin/env bash
# scripts/capture-evidence.sh — Machine-readable evidence capture.
# Aggregates all evidence JSON files into a single summary document.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${TOOL_DIR}/evidence"
mkdir -p "${EVIDENCE_DIR}"

TIMESTAMP=$(date -Iseconds)
HOSTNAME=$(hostname)
KERNEL=$(uname -r)
USER=$(whoami)

echo "=== Evidence Capture ==="
echo "timestamp: ${TIMESTAMP}"
echo "host:      ${HOSTNAME}"
echo "kernel:    ${KERNEL}"
echo ""

FILES=()
if [[ -d "${EVIDENCE_DIR}" ]]; then
    while IFS= read -r -d '' f; do
        FILES+=("$f")
    done < <(find "${EVIDENCE_DIR}" -name '*.json' -type f -print0 | sort -z)
fi

echo "Found ${#FILES[@]} evidence file(s):"
for f in "${FILES[@]}"; do
    echo "  $(basename "$f")"
done
echo ""

SUMMARY="{\"phase\":\"0-evidence-summary\",\"timestamp\":\"${TIMESTAMP}\",\"host\":\"${HOSTNAME}\",\"kernel\":\"${KERNEL}\",\"user\":\"${USER}\",\"evidence_files\":["
FIRST=true
for f in "${FILES[@]}"; do
    if [[ "${FIRST}" == "true" ]]; then
        FIRST=false
    else
        SUMMARY+=","
    fi
    BASENAME=$(basename "$f")
    SIZE=$(stat -c '%s' "$f" 2>/dev/null || echo 0)
    SUMMARY+="{\"file\":\"${BASENAME}\",\"size_bytes\":${SIZE}}"
done
SUMMARY+="]}"

OUTFILE="${EVIDENCE_DIR}/summary-$(date +%Y%m%dT%H%M%S).json"
echo "${SUMMARY}" | python3 -m json.tool > "${OUTFILE}" 2>/dev/null || echo "${SUMMARY}" > "${OUTFILE}"
echo "Summary written to: ${OUTFILE}"
