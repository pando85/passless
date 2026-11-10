#!/usr/bin/env bash
# Start/stop a hermetic Passless test instance (UHID virtual authenticator). Usage: passless-test-instance.sh start|stop|status
set -u
SC=${SPIKE_SCRATCH:-/home/agil/.cache/tmp/claude-1000/-home-agil-passkeys-passless/d4df783e-bb62-4ca3-b59c-9946f1a7ed88/scratchpad/envspike}
BIN=${PASSLESS_BIN:-/dev/shm/debug/passless}
PIDF=$SC/passless.pid
case ${1:-} in
  start)
    mkdir -p "$SC/home" "$SC/store"; : > "$SC/config.toml"
    before=$(ls /dev/hidraw* 2>/dev/null | sort)
    HOME=$SC/home PASSLESS_CONFIG=$SC/config.toml PASSLESS_BACKEND_TYPE=local PASSLESS_LOCAL_PATH=$SC/store \
    PASSLESS_E2E_AUTO_ACCEPT_UV=1 PASSLESS_E2E_AUTO_ACCEPT_STORAGE=1 \
      setsid dbus-run-session -- "$BIN" -v >"$SC/passless.log" 2>&1 &
    echo $! > "$PIDF"
    for i in $(seq 1 50); do sleep 0.2; after=$(ls /dev/hidraw* 2>/dev/null | sort); [ "$before" != "$after" ] && break; done
    echo "NOTE: other agents may run their own passless instances; verify via $SC/store and $SC/passless.log"
    echo "new hidraw: $(comm -13 <(echo "$before") <(echo "$after") | tr '\n' ' ')"
    ;;
  stop)
    [ -f "$PIDF" ] && { pid=$(cat "$PIDF"); kill -- -"$pid" 2>/dev/null; sleep 0.5; kill -9 -- -"$pid" 2>/dev/null; rm -f "$PIDF"; }
    echo "remaining in my process group: $(pgrep -g "${pid:-0}" -c 2>/dev/null || echo 0)" ;;
  status) [ -f "$PIDF" ] && pgrep -g "$(cat "$PIDF")" -a | cut -c1-160 ;;
esac
