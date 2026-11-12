#!/bin/bash

set -euo pipefail

PASSLESS_BIN="${AV_PASSLESS_BIN:?AV_PASSLESS_BIN is required}"
: "${AV_PROFILE_ID:?AV_PROFILE_ID is required}"
: "${AV_RP_ID:?AV_RP_ID is required}"
FLOW="${AV_PRINCIPAL_FLOW:?AV_PRINCIPAL_FLOW is required}"
COORD_DIR="${AV_COORD_DIR:?AV_COORD_DIR is required}"
TIMEOUT_SECS="${AV_FLOW_TIMEOUT_SECS:-90}"

[[ "$PASSLESS_BIN" == /* && -x "$PASSLESS_BIN" ]] || exit 2
[[ "$COORD_DIR" == /* && -d "$COORD_DIR" && ! -L "$COORD_DIR" ]] || exit 2
[[ "$TIMEOUT_SECS" =~ ^[0-9]+$ && "$TIMEOUT_SECS" -ge 5 && "$TIMEOUT_SECS" -le 300 ]] || exit 2

run_removed_flow() {
    # The principal intent protocol (`passless agent intent ...`, ADR 0014 P7) and the principal
    # delegation protocol (`passless agent delegation ...`) were removed. Agent ceremonies run
    # through the managed browser extension path (`passless agent browser`, `passless agent mcp`),
    # which this driver does not drive, so every flow fails closed instead of reporting a result.
    echo "principal-driver: the $1 flow was removed (ADR 0014); agents sign through the managed browser" >&2
    exit 3
}

case "$FLOW" in
    isolated) run_removed_flow isolated ;;
    same-user) run_removed_flow same-user ;;
    *) exit 2 ;;
esac
