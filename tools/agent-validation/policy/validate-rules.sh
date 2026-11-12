#!/usr/bin/env bash
# policy/validate-rules.sh — Dry-run validator for udev device isolation policy.
# Runs WITHOUT root. Proves generated rules do not grant principals /dev/uhid
# or foreign hidraw access.
#
# Checks:
#   PRIN-03  Principals (human operators) do NOT share a group with the daemon
#            for /dev/uhid.  The uhid rule must use a group distinct from the
#            human group.
#   ROUTE-03 Principals do NOT receive /dev/uhid.  No rule grants the human
#            group access to /dev/uhid.
#   ISOL-01  Probe hidraw nodes are accessible ONLY to the per-agent-profile
#            group, not to the general human group.
#   SETUP-01 setup.sh does NOT add the invoking user to the daemon group.
#   SETUP-02 setup.sh creates groups/users explicitly (no implicit grants).
#
# Exit code: 0 if all checks pass, 1 if any violation found.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULE_FILE="${SCRIPT_DIR}/90-uhid-feasibility.rules"
SETUP_FILE="${SCRIPT_DIR}/setup.sh"
CLEANUP_FILE="${SCRIPT_DIR}/cleanup.sh"
EVIDENCE_DIR="${SCRIPT_DIR}/../evidence"
mkdir -p "${EVIDENCE_DIR}"

HUMAN_GROUP="fido"
DAEMON_GROUP="uhid-daemon"
AGENT_GROUP="fido-agent-probe"

TIMESTAMP=$(date -Iseconds)
VIOLATIONS=0
CHECKS=()

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

record_check() {
    local name="$1" expected="$2" actual="$3" status="$4" detail="${5:-}"
    CHECKS+=("{\"name\":\"${name}\",\"expected\":\"$(json_escape "${expected}")\",\"actual\":\"$(json_escape "${actual}")\",\"status\":\"${status}\",\"detail\":\"$(json_escape "${detail}")\"}")
    if [[ "${status}" == "pass" ]]; then
        echo "  [PASS] ${name}: ${detail}"
    else
        echo "  [FAIL] ${name}: expected=${expected} actual=${actual} — ${detail}"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
}

echo "=== Policy Validation (dry-run, non-privileged) ==="
echo "timestamp: ${TIMESTAMP}"
echo "rule file: ${RULE_FILE}"
echo "setup:     ${SETUP_FILE}"
echo ""

if [[ ! -f "${RULE_FILE}" ]]; then
    echo "ERROR: rule file not found: ${RULE_FILE}" >&2
    exit 1
fi

if [[ ! -f "${SETUP_FILE}" ]]; then
    echo "ERROR: setup script not found: ${SETUP_FILE}" >&2
    exit 1
fi

echo "--- PRIN-03: Principal isolation from /dev/uhid ---"
UHID_RULE=$(grep -E 'KERNEL=="uhid"' "${RULE_FILE}" | grep -v '^#' || true)
if [[ -z "${UHID_RULE}" ]]; then
    record_check "PRIN-03_uhid_rule_exists" "rule present" "missing" "fail" \
        "No /dev/uhid rule found"
else
    UHID_GROUP_ASSIGN=$(echo "${UHID_RULE}" | grep -oP 'GROUP="\K[^"]+' || true)
    if [[ -z "${UHID_GROUP_ASSIGN}" ]]; then
        record_check "PRIN-03_uhid_group_set" "group assigned" "none" "fail" \
            "/dev/uhid rule has no GROUP= assignment"
    elif [[ "${UHID_GROUP_ASSIGN}" == "${HUMAN_GROUP}" ]]; then
        record_check "PRIN-03_uhid_group_disjoint" "!=${HUMAN_GROUP}" "${UHID_GROUP_ASSIGN}" "fail" \
            "/dev/uhid uses human group '${HUMAN_GROUP}' — principals share daemon access"
    else
        record_check "PRIN-03_uhid_group_disjoint" "!=${HUMAN_GROUP}" "${UHID_GROUP_ASSIGN}" "pass" \
            "/dev/uhid uses '${UHID_GROUP_ASSIGN}', not '${HUMAN_GROUP}'"
    fi
fi

echo ""
echo "--- ROUTE-03: Principals do NOT receive /dev/uhid ---"
UHID_HUMAN_MATCH=$(grep -E 'KERNEL=="uhid"' "${RULE_FILE}" | grep -v '^#' | grep "GROUP=\"${HUMAN_GROUP}\"" || true)
if [[ -n "${UHID_HUMAN_MATCH}" ]]; then
    record_check "ROUTE-03_no_uhid_for_humans" "no match" "matched" "fail" \
        "/dev/uhid rule grants '${HUMAN_GROUP}' access"
else
    record_check "ROUTE-03_no_uhid_for_humans" "no match" "no match" "pass" \
        "No /dev/uhid rule grants '${HUMAN_GROUP}' access"
fi

echo ""
echo "--- ISOL-01: Probe hidraw scoped to per-agent-profile group ---"
PROBE_HIDRAW_RULE=$(grep -E 'SUBSYSTEM=="hidraw".*FEASIBILITY_PROBE' "${RULE_FILE}" | grep -v '^#' || true)
if [[ -z "${PROBE_HIDRAW_RULE}" ]]; then
    record_check "ISOL-01_probe_hidraw_rule" "rule present" "missing" "fail" \
        "No probe hidraw rule found"
else
    PROBE_GROUP_ASSIGN=$(echo "${PROBE_HIDRAW_RULE}" | grep -oP 'GROUP="\K[^"]+' || true)
    if [[ -z "${PROBE_GROUP_ASSIGN}" ]]; then
        record_check "ISOL-01_probe_hidraw_group" "group assigned" "none" "fail" \
            "Probe hidraw rule has no GROUP= assignment"
    elif [[ "${PROBE_GROUP_ASSIGN}" == "${HUMAN_GROUP}" ]]; then
        record_check "ISOL-01_probe_hidraw_group" "!=${HUMAN_GROUP}" "${PROBE_GROUP_ASSIGN}" "fail" \
            "Probe hidraw uses human group '${HUMAN_GROUP}' — not scoped to agent profile"
    elif [[ "${PROBE_GROUP_ASSIGN}" == "${DAEMON_GROUP}" ]]; then
        record_check "ISOL-01_probe_hidraw_group" "!=${DAEMON_GROUP}" "${PROBE_GROUP_ASSIGN}" "fail" \
            "Probe hidraw uses daemon group '${DAEMON_GROUP}' — should be agent-profile group"
    else
        record_check "ISOL-01_probe_hidraw_group" "agent-profile group" "${PROBE_GROUP_ASSIGN}" "pass" \
            "Probe hidraw uses '${PROBE_GROUP_ASSIGN}' (per-agent-profile)"
    fi
fi

echo ""
echo "--- PROBE-01: Probe udev rule must NOT match human product 0a37 ---"
PROBE_TAG_RULE=$(grep -E 'FEASIBILITY_PROBE' "${RULE_FILE}" | grep -E 'SUBSYSTEM=="hid"' | grep -v '^#' || true)
if [[ -z "${PROBE_TAG_RULE}" ]]; then
    record_check "PROBE-01_probe_tag_rule" "rule present" "missing" "fail" \
        "No HID probe tagging rule found"
else
    PROBE_PRODUCT=$(echo "${PROBE_TAG_RULE}" | grep -oP 'idProduct\}=="\K[^"]+' || true)
    if [[ "${PROBE_PRODUCT}" == "0a37" ]]; then
        record_check "PROBE-01_no_human_product" "!=0a37" "0a37" "fail" \
            "Probe rule matches human product 0a37 — will tag human device"
    elif [[ -n "${PROBE_PRODUCT}" ]]; then
        record_check "PROBE-01_no_human_product" "!=0a37" "${PROBE_PRODUCT}" "pass" \
            "Probe rule uses product '${PROBE_PRODUCT}', not human '0a37'"
    else
        record_check "PROBE-01_probe_product_set" "product set" "none" "fail" \
            "Probe tagging rule has no idProduct match"
    fi
fi

echo ""
echo "--- SETUP-01: setup.sh does NOT add human to daemon group ---"
SETUP_ADDS_DAEMON=$(grep -E "usermod.*-a?G.*${DAEMON_GROUP}.*SUDO_USER|usermod.*-a?G.*${DAEMON_GROUP}.*\$\{" "${SETUP_FILE}" | grep -v '^#' || true)
if [[ -n "${SETUP_ADDS_DAEMON}" ]]; then
    record_check "SETUP-01_no_human_in_daemon_group" "no match" "matched" "fail" \
        "setup.sh adds SUDO_USER to '${DAEMON_GROUP}'"
else
    record_check "SETUP-01_no_human_in_daemon_group" "no match" "no match" "pass" \
        "setup.sh does not add human user to '${DAEMON_GROUP}'"
fi

echo ""
echo "--- SETUP-02: setup.sh creates groups/users explicitly ---"
EXPLICIT_GROUPS=0
for g in DAEMON_GROUP HUMAN_GROUP AGENT_GROUP; do
    VAR_VAL="${!g}"
    if grep -qE "groupadd.*\\$\{${g}\}|groupadd.*${VAR_VAL}" "${SETUP_FILE}" 2>/dev/null; then
        EXPLICIT_GROUPS=$((EXPLICIT_GROUPS + 1))
    fi
done
if [[ ${EXPLICIT_GROUPS} -eq 3 ]]; then
    record_check "SETUP-02_explicit_group_creation" "3 groups" "3 groups" "pass" \
        "All 3 groups created explicitly: ${DAEMON_GROUP}, ${HUMAN_GROUP}, ${AGENT_GROUP}"
else
    record_check "SETUP-02_explicit_group_creation" "3 groups" "${EXPLICIT_GROUPS} groups" "fail" \
        "Expected 3 explicit groupadd calls, found ${EXPLICIT_GROUPS}"
fi

HAS_USERADD=$(grep -c "useradd" "${SETUP_FILE}" 2>/dev/null || true)
HAS_USERADD="${HAS_USERADD:-0}"
HAS_DAEMON_USER_VAR=$(grep -c "DAEMON_USER" "${SETUP_FILE}" 2>/dev/null || true)
HAS_DAEMON_USER_VAR="${HAS_DAEMON_USER_VAR:-0}"
if [[ "${HAS_USERADD}" -ge 1 && "${HAS_DAEMON_USER_VAR}" -ge 1 ]]; then
    record_check "SETUP-02_explicit_user_creation" ">=1" "useradd+DAEMON_USER" "pass" \
        "Daemon user created explicitly"
else
    record_check "SETUP-02_explicit_user_creation" ">=1" "useradd=${HAS_USERADD},DAEMON_USER=${HAS_DAEMON_USER_VAR}" "fail" \
        "No explicit useradd for daemon user"
fi

echo ""
echo "--- SETUP-03: setup.sh removes human from daemon group if present ---"
REMOVAL_CHECK=$(grep -cE "gpasswd -d.*DAEMON_GROUP|deluser.*DAEMON_GROUP|gpasswd -d.*uhid-daemon" "${SETUP_FILE}" 2>/dev/null || true)
REMOVAL_CHECK="${REMOVAL_CHECK:-0}"
if [[ "${REMOVAL_CHECK}" -ge 1 ]]; then
    record_check "SETUP-03_removes_human_from_daemon" ">=1" "${REMOVAL_CHECK}" "pass" \
        "setup.sh checks and removes human from daemon group"
else
    record_check "SETUP-03_removes_human_from_daemon" ">=1" "0" "fail" \
        "setup.sh does not check/remove human from daemon group"
fi

echo ""
echo "--- CLEANUP-01: cleanup.sh uses state file for safe removal ---"
if [[ -f "${CLEANUP_FILE}" ]]; then
    STATE_REF=$(grep -cE "STATE_FILE|setup.state" "${CLEANUP_FILE}" 2>/dev/null || true)
    STATE_REF="${STATE_REF:-0}"
    if [[ "${STATE_REF}" -ge 1 ]]; then
        record_check "CLEANUP-01_state_based_cleanup" ">=1" "${STATE_REF}" "pass" \
            "cleanup.sh reads state file for safe removal"
    else
        record_check "CLEANUP-01_state_based_cleanup" ">=1" "0" "fail" \
            "cleanup.sh does not use state file"
    fi
else
    record_check "CLEANUP-01_cleanup_exists" "file present" "missing" "fail" \
        "cleanup.sh not found"
fi

echo ""
echo "--- Group separation matrix ---"
echo "  /dev/uhid      → GROUP=${UHID_GROUP_ASSIGN:-UNSET}  (daemon only)"
echo "  probe hidraw   → GROUP=${PROBE_GROUP_ASSIGN:-UNSET}  (per-agent-profile)"
echo "  human group    → ${HUMAN_GROUP}  (NOT /dev/uhid, NOT probe hidraw)"
echo ""

TOTAL_CHECKS=${#CHECKS[@]}
PASSED=$((TOTAL_CHECKS - VIOLATIONS))

CHECKS_JSON=$(IFS=,; echo "${CHECKS[*]}")
JSON="{\"phase\":\"0-policy-validation\",\"timestamp\":\"${TIMESTAMP}\",\"rule_file\":\"${RULE_FILE}\",\"setup_file\":\"${SETUP_FILE}\",\"human_group\":\"${HUMAN_GROUP}\",\"daemon_group\":\"${DAEMON_GROUP}\",\"agent_group\":\"${AGENT_GROUP}\",\"uhid_group\":\"${UHID_GROUP_ASSIGN:-unset}\",\"probe_hidraw_group\":\"${PROBE_GROUP_ASSIGN:-unset}\",\"total_checks\":${TOTAL_CHECKS},\"passed\":${PASSED},\"violations\":${VIOLATIONS},\"checks\":[${CHECKS_JSON}]}"

OUTFILE="${EVIDENCE_DIR}/policy-validation-$(date +%Y%m%dT%H%M%S).json"
echo "${JSON}" | python3 -m json.tool > "${OUTFILE}" 2>/dev/null || echo "${JSON}" > "${OUTFILE}"

echo "=== Result: ${PASSED}/${TOTAL_CHECKS} passed, ${VIOLATIONS} violations ==="
echo "Evidence written to: ${OUTFILE}"

if [[ ${VIOLATIONS} -gt 0 ]]; then
    echo ""
    echo "FAIL: Policy violations detected." >&2
    exit 1
else
    echo ""
    echo "PASS: All policy constraints satisfied."
    exit 0
fi
