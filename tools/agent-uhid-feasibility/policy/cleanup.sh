#!/usr/bin/env bash
# policy/cleanup.sh — Privileged cleanup for UHID feasibility probe.
# Requires: root (sudo).
#
# Safely removes ONLY resources created by setup.sh, using the state file.
# Will never remove pre-existing groups or users.
#
# Actions:
#   1. Remove installed udev rule
#   2. Reload udev rules
#   3. Remove daemon user (only if created by setup)
#   4. Remove groups (only if created by setup)
#   5. Scan for and report leftover probe devices in sysfs
#   6. Remove state file
set -euo pipefail

RULE_DST="/etc/udev/rules.d/90-uhid-feasibility.rules"
STATE_FILE="/var/lib/passless-feasibility/setup.state"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (use sudo)" >&2
    exit 1
fi

echo "==> Reading state file"
if [[ -f "${STATE_FILE}" ]]; then
    # shellcheck source=/dev/null
    source "${STATE_FILE}"
    echo "    loaded state from ${STATE_FILE}"
else
    echo "    no state file found at ${STATE_FILE}"
    echo "    proceeding with best-effort cleanup of known resources"
    CREATED_GROUPS="uhid-daemon,fido-agent-probe"
    CREATED_USERS="passless-daemon"
    INSTALLED_RULE="true"
fi

echo "==> Removing udev rule"
if [[ "${INSTALLED_RULE:-false}" == "true" && -f "${RULE_DST}" ]]; then
    rm -f "${RULE_DST}"
    echo "    removed ${RULE_DST}"
elif [[ -f "${RULE_DST}" ]]; then
    rm -f "${RULE_DST}"
    echo "    removed ${RULE_DST} (found on disk)"
else
    echo "    rule not present, skipping"
fi

echo "==> Reloading udev rules"
udevadm control --reload-rules 2>/dev/null || true

echo "==> Removing daemon user (if created by setup)"
if [[ -n "${CREATED_USERS:-}" ]]; then
    IFS=',' read -ra USERS <<< "${CREATED_USERS}"
    for u in "${USERS[@]}"; do
        [[ -z "${u}" ]] && continue
        if id "${u}" >/dev/null 2>&1; then
            userdel "${u}" 2>/dev/null && echo "    removed user '${u}'" || echo "    WARNING: could not remove user '${u}'"
        else
            echo "    user '${u}' does not exist, skipping"
        fi
    done
else
    echo "    no users to remove"
fi

echo "==> Removing groups (if created by setup)"
if [[ -n "${CREATED_GROUPS:-}" ]]; then
    IFS=',' read -ra GROUPS <<< "${CREATED_GROUPS}"
    for g in "${GROUPS[@]}"; do
        [[ -z "${g}" ]] && continue
        if getent group "${g}" >/dev/null 2>&1; then
            MEMBERS=$(getent group "${g}" | cut -d: -f4)
            if [[ -n "${MEMBERS}" ]]; then
                echo "    WARNING: group '${g}' still has members: ${MEMBERS}"
                echo "    skipping removal to avoid breaking other services"
            else
                groupdel "${g}" 2>/dev/null && echo "    removed group '${g}'" || echo "    WARNING: could not remove group '${g}'"
            fi
        else
            echo "    group '${g}' does not exist, skipping"
        fi
    done
else
    echo "    no groups to remove"
fi

echo "==> Scanning for leftover probe devices"
LEFTOVER=0
if [[ -d /sys/bus/hid/devices ]]; then
    for dev in /sys/bus/hid/devices/*/; do
        if [[ -f "${dev}uevent" ]]; then
            NAME=$(grep -oP '(?<=HID_NAME=).*' "${dev}uevent" 2>/dev/null || true)
            if [[ "${NAME}" == *"feasibility-probe"* || "${NAME}" == *"feasibility-cycle"* || "${NAME}" == *"feasibility-concurrent"* || "${NAME}" == *"agent-uhid"* ]]; then
                echo "    LEFTOVER: ${dev} (name=${NAME})"
                LEFTOVER=$((LEFTOVER + 1))
            fi
        fi
    done
fi
if [[ ${LEFTOVER} -eq 0 ]]; then
    echo "    no leftover probe devices"
else
    echo "    WARNING: ${LEFTOVER} leftover device(s) found"
fi

echo "==> Checking uhid module usage"
if [[ -f /proc/modules ]]; then
    REFCNT=$(awk '/^uhid /{print $3}' /proc/modules 2>/dev/null || echo "?")
    echo "    uhid refcount: ${REFCNT}"
    if [[ "${REFCNT}" == "0" ]]; then
        echo "    uhid module has 0 references; not unloading (safe to keep loaded)"
    fi
fi

echo "==> Removing state file"
if [[ -f "${STATE_FILE}" ]]; then
    rm -f "${STATE_FILE}"
    echo "    removed ${STATE_FILE}"
else
    echo "    no state file to remove"
fi

echo ""
echo "Cleanup complete."
