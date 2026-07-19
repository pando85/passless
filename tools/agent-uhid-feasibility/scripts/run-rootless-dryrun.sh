#!/usr/bin/env bash
# scripts/run-rootless-dryrun.sh — Non-privileged feasibility checks.
# Runs without root. Records machine-readable JSON to stdout and to evidence file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${TOOL_DIR}/evidence"
mkdir -p "${EVIDENCE_DIR}"

TIMESTAMP=$(date -Iseconds)
HOSTNAME=$(hostname)
KERNEL=$(uname -r)
USER=$(whoami)
UID_VAL=$(id -u)
GID_VAL=$(id -g)
GROUPS_LIST=$(id -G)

BIN="${CARGO_TARGET_DIR:-${TOOL_DIR}/target}/debug/uhid-feasibility"
if [[ ! -x "${BIN}" ]]; then
    BIN=$(find "${TOOL_DIR}" -path "*/debug/uhid-feasibility" -type f -executable 2>/dev/null | head -1)
fi
if [[ ! -x "${BIN}" ]]; then
    BIN=$(find /dev/shm -name "uhid-feasibility" -type f -executable 2>/dev/null | head -1)
fi

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

echo "=== Rootless Dry-Run ==="
echo "timestamp: ${TIMESTAMP}"
echo "host:      ${HOSTNAME}"
echo "kernel:    ${KERNEL}"
echo "user:      ${USER} (uid=${UID_VAL}, gid=${GID_VAL})"
echo "groups:    ${GROUPS_LIST}"
echo "binary:    ${BIN:-NOT_FOUND}"
echo ""

CHECKS=()
run_check() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    local status="fail"
    if [[ "${actual}" == "${expected}" ]]; then
        status="pass"
    fi
    CHECKS+=("{\"name\":\"${name}\",\"expected\":\"${expected}\",\"actual\":\"$(json_escape "${actual}")\",\"status\":\"${status}\",\"privileged\":false}")
    echo "  [${status^^}] ${name}: expected=${expected} actual=${actual}"
}

echo "--- Kernel module ---"
if [[ -d /sys/module/uhid ]]; then
    run_check "uhid_module_in_sysfs" "true" "true"
else
    run_check "uhid_module_in_sysfs" "true" "false"
fi

if grep -q '^uhid ' /proc/modules 2>/dev/null; then
    run_check "uhid_module_in_proc_modules" "true" "true"
else
    run_check "uhid_module_in_proc_modules" "true" "false"
fi

echo ""
echo "--- Device nodes ---"
if [[ -e /dev/uhid ]]; then
    run_check "dev_uhid_exists" "true" "true"
    UHID_MODE=$(stat -c '%a' /dev/uhid 2>/dev/null || echo "unknown")
    UHID_OWNER=$(stat -c '%U:%G' /dev/uhid 2>/dev/null || echo "unknown")
    run_check "dev_uhid_mode" "660" "${UHID_MODE}"
    run_check "dev_uhid_owner" "root:fido" "${UHID_OWNER}"

    if [[ -r /dev/uhid ]]; then
        run_check "dev_uhid_readable" "true" "true"
    else
        run_check "dev_uhid_readable" "true" "false"
    fi
    if [[ -w /dev/uhid ]]; then
        run_check "dev_uhid_writable" "true" "true"
    else
        run_check "dev_uhid_writable" "true" "false"
    fi
else
    run_check "dev_uhid_exists" "true" "false"
    run_check "dev_uhid_readable" "true" "false"
    run_check "dev_uhid_writable" "true" "false"
fi

echo ""
echo "--- hidraw nodes ---"
HIDRAW_COUNT=0
HIDRAW_RW=0
for f in /dev/hidraw*; do
    [[ -e "$f" ]] || continue
    HIDRAW_COUNT=$((HIDRAW_COUNT + 1))
    if [[ -r "$f" && -w "$f" ]]; then
        HIDRAW_RW=$((HIDRAW_RW + 1))
    fi
done
run_check "hidraw_count_gte_1" "true" "$([[ ${HIDRAW_COUNT} -ge 1 ]] && echo true || echo false)"
echo "  hidraw devices: ${HIDRAW_COUNT} (rw-accessible: ${HIDRAW_RW})"

echo ""
echo "--- sysfs HID bus ---"
if [[ -d /sys/bus/hid/devices ]]; then
    run_check "sysfs_hid_bus_exists" "true" "true"
    HID_DEV_COUNT=$(ls -1 /sys/bus/hid/devices/ 2>/dev/null | wc -l)
    echo "  HID devices in sysfs: ${HID_DEV_COUNT}"
else
    run_check "sysfs_hid_bus_exists" "true" "false"
fi

echo ""
echo "--- fido group membership ---"
if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx fido; then
    run_check "user_in_fido_group" "true" "true"
else
    run_check "user_in_fido_group" "true" "false"
fi

echo ""
echo "--- Binary availability ---"
if [[ -x "${BIN:-}" ]]; then
    run_check "binary_exists" "true" "true"
    echo ""
    echo "--- Tool: env command ---"
    ENV_OUT=$("${BIN}" env 2>&1) || true
    echo "${ENV_OUT}"

    echo ""
    echo "--- Tool: discover command ---"
    DISCOVER_OUT=$("${BIN}" discover 2>&1) || true
    echo "${DISCOVER_OUT}"

    echo ""
    echo "--- Tool: hidraw-map command ---"
    HIDRAW_MAP_OUT=$("${BIN}" hidraw-map 2>&1) || true
    echo "${HIDRAW_MAP_OUT}"

    echo ""
    echo "--- Tool: cleanup command ---"
    CLEANUP_OUT=$("${BIN}" cleanup 2>&1) || true
    echo "${CLEANUP_OUT}"
else
    run_check "binary_exists" "true" "false"
    ENV_OUT=""
    DISCOVER_OUT=""
    HIDRAW_MAP_OUT=""
    CLEANUP_OUT=""
fi

CHECKS_JSON=$(IFS=,; echo "${CHECKS[*]}")
JSON="{\"phase\":\"0-rootless-dryrun\",\"timestamp\":\"${TIMESTAMP}\",\"host\":\"${HOSTNAME}\",\"kernel\":\"${KERNEL}\",\"user\":\"${USER}\",\"uid\":${UID_VAL},\"gid\":${GID_VAL},\"groups\":\"${GROUPS_LIST}\",\"binary\":\"${BIN:-not_found}\",\"hidraw_count\":${HIDRAW_COUNT},\"checks\":[${CHECKS_JSON}]}"

OUTFILE="${EVIDENCE_DIR}/rootless-dryrun-$(date +%Y%m%dT%H%M%S).json"
echo "${JSON}" | python3 -m json.tool > "${OUTFILE}" 2>/dev/null || echo "${JSON}" > "${OUTFILE}"
echo ""
echo "Evidence written to: ${OUTFILE}"
