#!/usr/bin/env bash
# policy/setup.sh — Privileged setup for UHID feasibility probe isolation.
# Requires: root (sudo).
#
# Identity model (PRIN-03, ROUTE-03 compliant):
#   - uhid-daemon group   : daemon-only /dev/uhid R/W
#   - passless-daemon user: system account for the daemon (member of uhid-daemon)
#   - fido group          : human operators (hidraw only, NOT /dev/uhid)
#   - fido-agent-probe    : per-agent-profile group for probe hidraw R/W
#
# Actions:
#   1. Load uhid kernel module if not present
#   2. Create groups explicitly (uhid-daemon, fido, fido-agent-probe)
#   3. Create daemon system user (passless-daemon) in uhid-daemon group
#   4. Add invoking user to fido group ONLY (not uhid-daemon)
#   5. Install deterministic udev rule
#   6. Reload udev rules and trigger
#   7. Verify /dev/uhid permissions
#   8. Write state file for safe cleanup
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULE_FILE="90-uhid-feasibility.rules"
RULE_SRC="${SCRIPT_DIR}/${RULE_FILE}"
RULE_DST="/etc/udev/rules.d/${RULE_FILE}"
STATE_FILE="/var/lib/passless-feasibility/setup.state"

DAEMON_USER="passless-daemon"
DAEMON_GROUP="uhid-daemon"
HUMAN_GROUP="fido"
AGENT_GROUP="fido-agent-probe"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (use sudo)" >&2
    exit 1
fi

mkdir -p "$(dirname "${STATE_FILE}")"

declare -a CREATED_GROUPS=()
declare -a CREATED_USERS=()
INSTALLED_RULE="false"

cleanup_on_error() {
    echo "ERROR: setup failed, rolling back..." >&2
    for u in "${CREATED_USERS[@]}"; do
        userdel "${u}" 2>/dev/null || true
    done
    for g in "${CREATED_GROUPS[@]}"; do
        groupdel "${g}" 2>/dev/null || true
    done
    if [[ "${INSTALLED_RULE}" == "true" && -f "${RULE_DST}" ]]; then
        rm -f "${RULE_DST}"
    fi
    rm -f "${STATE_FILE}"
    exit 1
}
trap cleanup_on_error ERR

echo "==> Loading uhid kernel module"
modprobe uhid 2>/dev/null || true

if [[ ! -e /sys/module/uhid ]]; then
    echo "ERROR: uhid module not available after modprobe" >&2
    exit 1
fi
echo "    uhid module loaded"

echo "==> Creating '${DAEMON_GROUP}' group (daemon /dev/uhid access)"
if ! getent group "${DAEMON_GROUP}" >/dev/null 2>&1; then
    groupadd --system "${DAEMON_GROUP}"
    CREATED_GROUPS+=("${DAEMON_GROUP}")
    echo "    created system group '${DAEMON_GROUP}' (gid=$(getent group "${DAEMON_GROUP}" | cut -d: -f3))"
else
    echo "    group '${DAEMON_GROUP}' already exists (gid=$(getent group "${DAEMON_GROUP}" | cut -d: -f3))"
fi

echo "==> Creating '${HUMAN_GROUP}' group (human operator hidraw access)"
if ! getent group "${HUMAN_GROUP}" >/dev/null 2>&1; then
    groupadd "${HUMAN_GROUP}"
    CREATED_GROUPS+=("${HUMAN_GROUP}")
    echo "    created group '${HUMAN_GROUP}' (gid=$(getent group "${HUMAN_GROUP}" | cut -d: -f3))"
else
    echo "    group '${HUMAN_GROUP}' already exists (gid=$(getent group "${HUMAN_GROUP}" | cut -d: -f3))"
fi

echo "==> Creating '${AGENT_GROUP}' group (per-agent-profile probe hidraw)"
if ! getent group "${AGENT_GROUP}" >/dev/null 2>&1; then
    groupadd --system "${AGENT_GROUP}"
    CREATED_GROUPS+=("${AGENT_GROUP}")
    echo "    created system group '${AGENT_GROUP}' (gid=$(getent group "${AGENT_GROUP}" | cut -d: -f3))"
else
    echo "    group '${AGENT_GROUP}' already exists (gid=$(getent group "${AGENT_GROUP}" | cut -d: -f3))"
fi

echo "==> Creating '${DAEMON_USER}' system user (daemon service account)"
if ! id "${DAEMON_USER}" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --gid "${DAEMON_GROUP}" "${DAEMON_USER}"
    CREATED_USERS+=("${DAEMON_USER}")
    echo "    created system user '${DAEMON_USER}' (uid=$(id -u "${DAEMON_USER}"))"
else
    echo "    user '${DAEMON_USER}' already exists (uid=$(id -u "${DAEMON_USER}"))"
    if ! id -nG "${DAEMON_USER}" | tr ' ' '\n' | grep -qx "${DAEMON_GROUP}"; then
        usermod -aG "${DAEMON_GROUP}" "${DAEMON_USER}"
        echo "    added '${DAEMON_USER}' to '${DAEMON_GROUP}'"
    fi
fi

if [[ -n "${SUDO_USER:-}" ]]; then
    echo "==> Adding user '${SUDO_USER}' to '${HUMAN_GROUP}' group ONLY"
    echo "    (PRIN-03: human operators do NOT get uhid-daemon or /dev/uhid access)"
    usermod -aG "${HUMAN_GROUP}" "${SUDO_USER}" || true
    echo "    added '${SUDO_USER}' to '${HUMAN_GROUP}'"

    if id -nG "${SUDO_USER}" | tr ' ' '\n' | grep -qx "${DAEMON_GROUP}"; then
        echo "    WARNING: '${SUDO_USER}' is in '${DAEMON_GROUP}' — removing (PRIN-03 violation)"
        gpasswd -d "${SUDO_USER}" "${DAEMON_GROUP}" || true
    fi
fi

echo "==> Installing udev rule"
cp "${RULE_SRC}" "${RULE_DST}"
INSTALLED_RULE="true"
echo "    installed ${RULE_DST}"

echo "==> Reloading udev rules"
udevadm control --reload-rules
udevadm trigger --subsystem-match=misc --subsystem-match=hid --subsystem-match=hidraw
echo "    udev rules reloaded and triggered"

echo "==> Verifying /dev/uhid"
if [[ -e /dev/uhid ]]; then
    PERMS=$(stat -c '%a %U:%G' /dev/uhid)
    echo "    /dev/uhid: ${PERMS}"
    UHID_GROUP=$(stat -c '%G' /dev/uhid)
    if [[ "${UHID_GROUP}" != "${DAEMON_GROUP}" ]]; then
        echo "    WARNING: /dev/uhid group is '${UHID_GROUP}', expected '${DAEMON_GROUP}'"
        echo "    Try: udevadm trigger --subsystem-match=misc"
    fi
else
    echo "    WARNING: /dev/uhid does not exist (module may need device node creation)"
fi

echo "==> Writing state file for cleanup"
{
    echo "CREATED_GROUPS=$(IFS=,; echo "${CREATED_GROUPS[*]}")"
    echo "CREATED_USERS=$(IFS=,; echo "${CREATED_USERS[*]}")"
    echo "INSTALLED_RULE=${INSTALLED_RULE}"
    echo "DAEMON_USER=${DAEMON_USER}"
    echo "DAEMON_GROUP=${DAEMON_GROUP}"
    echo "HUMAN_GROUP=${HUMAN_GROUP}"
    echo "AGENT_GROUP=${AGENT_GROUP}"
} > "${STATE_FILE}"
echo "    state written to ${STATE_FILE}"

echo ""
echo "Setup complete."
echo ""
echo "Identity summary:"
echo "  /dev/uhid       → GROUP=${DAEMON_GROUP} (daemon only, PRIN-03/ROUTE-03)"
echo "  probe hidraw    → GROUP=${AGENT_GROUP} (per-agent-profile, ISOL-01)"
echo "  human operators → GROUP=${HUMAN_GROUP} (hidraw only, NOT /dev/uhid)"
echo ""
if [[ -n "${SUDO_USER:-}" ]]; then
    echo "User '${SUDO_USER}' added to '${HUMAN_GROUP}' only."
    echo "Re-login or run: newgrp ${HUMAN_GROUP}"
fi
