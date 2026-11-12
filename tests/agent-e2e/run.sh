#!/usr/bin/env bash
# Agent-delegation E2E runner (see README.md).
#
# Selection (environment):
#   AGENT_E2E_MATRIX=ci|full        ci (default): CI-tagged scenarios on one browser, headless. full: everything.
#   AGENT_E2E_BROWSERS=a,b          chromium, pw-chromium, cft (negative controls: chrome, headless-shell)
#   AGENT_E2E_HEADLESS=new|headed|both
#   AGENT_E2E_EXPOSE=port|pipe|all  CDP exposure (attach mode) axis: ci default port, full default all (a scenario runs once per mode it supports)
#   AGENT_E2E_FILTER=E2E-01,6       scenario ids (also accepted as arguments); overrides the CI selection
#   AGENT_E2E_ALLOW_SKIP=1          a SKIP no longer fails the run (optional tools / missing browsers)
#   AGENT_E2E_TIMEOUT=SECONDS       overall limit (default 900 for ci, 14400 for full)
#
# Hermeticity: the whole run happens inside a private `dbus-run-session` started from a MINIMAL bus config (no
# service directories, so nothing can be bus-activated), with a scrubbed environment (temp HOME/XDG_*, no
# DISPLAY/WAYLAND_DISPLAY/XAUTHORITY). Only headed variants get a DISPLAY, the one from `xvfb-run`.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=tests/agent-e2e/lib/limit.sh
source "$HERE/lib/limit.sh"

if [[ $# -gt 0 ]]; then
  AGENT_E2E_FILTER="$(IFS=,; echo "$*")"
  export AGENT_E2E_FILTER
fi
export AGENT_E2E_MATRIX="${AGENT_E2E_MATRIX:-ci}"

want_headed() {
  case "${AGENT_E2E_HEADLESS:-}" in
    headed|both|*headed*) return 0 ;;
    "") [[ "$AGENT_E2E_MATRIX" == "full" ]] && return 0 || return 1 ;;
    *) return 1 ;;
  esac
}

if [[ -z "${AGENT_E2E_INNER:-}" ]]; then
  # ---- outer phase: real environment, no scenario code runs here ----
  missing=()
  for tool in node npm dbus-run-session dbus-send openssl bwrap flock; do command -v "$tool" >/dev/null || missing+=("$tool"); done
  if want_headed; then command -v xvfb-run >/dev/null || missing+=("xvfb-run"); fi
  if (( ${#missing[@]} )); then echo "missing prerequisites: ${missing[*]}" >&2; exit 2; fi
  [[ -r /dev/uhid && -w /dev/uhid ]] || { echo "/dev/uhid is not accessible (modprobe uhid; join the fido group, see README.md)" >&2; exit 2; }
  node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' || { echo "Node 20+ required" >&2; exit 2; }

  # Nothing in the outer phase (builds, downloads, the guard) may use the session bus this run was started
  # with. Keep its address only so the harness can refuse it, then point everything at a dead bus until
  # the private one exists.
  REAL_BUS="${DBUS_SESSION_BUS_ADDRESS:-}"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent/passless-agent-e2e-outer-bus"

  CACHE="$REPO/target/agent-e2e-cache"
  mkdir -p "$CACHE" "$REPO/target"
  export npm_config_cache="$CACHE/npm"

  # Dependencies: re-run `npm ci` whenever package-lock.json changed.
  lockhash="$(sha256sum package-lock.json | cut -d' ' -f1)"
  if [[ ! -d node_modules || "$(cat node_modules/.lock-hash 2>/dev/null || true)" != "$lockhash" ]]; then
    npm ci --no-audit --no-fund
    echo "$lockhash" > node_modules/.lock-hash
  fi

  # Build the binaries and fetch browsers once, under a lock so concurrent runs do not race on the shared
  # cache and build dirs. A failed build aborts the run.
  exec 9>"$REPO/target/agent-e2e.lock"
  flock 9
  build_out="$(node lib/build.js)" || { echo "build failed; aborting" >&2; exit 1; }
  eval "$(sed 's/^/export /' <<<"$build_out")"
  node lib/prefetch.js || { echo "browser prefetch failed; aborting" >&2; exit 1; }
  flock -u 9

  RUN_ROOT="$(mktemp -d /tmp/pl-run-XXXXXX)"
  snap="$RUN_ROOT/guard.json"
  trap 'rm -rf "$RUN_ROOT"' EXIT
  mkdir -p "$RUN_ROOT"/{home,config,state,data,cache,run}
  chmod 700 "$RUN_ROOT" "$RUN_ROOT/run"

  # Minimal private bus: session type, a socket in the temp dir, EXTERNAL auth, allow-all policy and NO
  # <servicedir>/<standard_session_servicedirs/> (so no service can be activated).
  cat > "$RUN_ROOT/bus.conf" <<CONF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=$RUN_ROOT/bus.sock</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
    <allow user="*"/>
  </policy>
</busconfig>
CONF

  export AGENT_E2E_TLS_DIR="$RUN_ROOT/tls"
  node -e 'require("./lib/tls").ensureTestTls()'

  others=$(pgrep -x passless | wc -l || true)
  if (( others > 0 )); then
    echo "note: $others other passless process(es) are running; this run only uses its own UHID device (identified through sysfs) and fails if that is ambiguous." >&2
  fi

  node lib/guard.js snapshot "$snap"
  export AGENT_E2E_RESULTS="${AGENT_E2E_RESULTS:-$(mktemp)}"
  : > "$AGENT_E2E_RESULTS"

  if [[ "$AGENT_E2E_MATRIX" == "full" ]]; then default_timeout=14400; else default_timeout=900; fi
  limit="${AGENT_E2E_TIMEOUT:-$default_timeout}"

  # Scrubbed environment: only what the harness needs, plus every AGENT_E2E_* setting. The real bus address is
  # passed as AGENT_E2E_REAL_BUS purely so the harness can refuse to ever use it.
  fwd=()
  while IFS= read -r name; do fwd+=("$name=${!name}"); done < <(compgen -e | grep -E '^(AGENT_E2E_|npm_config_cache$)' || true)
  clean_env=(env -i "PATH=$PATH" "LANG=${LANG:-C.UTF-8}" "HOME=$RUN_ROOT/home" "XDG_CONFIG_HOME=$RUN_ROOT/config"
    "XDG_STATE_HOME=$RUN_ROOT/state" "XDG_DATA_HOME=$RUN_ROOT/data" "XDG_DATA_DIRS=$RUN_ROOT/data" "XDG_CACHE_HOME=$RUN_ROOT/cache"
    "XDG_RUNTIME_DIR=$RUN_ROOT/run" "AGENT_E2E_REAL_BUS=$REAL_BUS" "${fwd[@]}")

  # The overall limit is a bash-native watchdog (lib/limit.sh): no `timeout` process for a stray `pkill -x timeout` to
  # hit, and no renamed coreutils binary (uutils refuses to run under a name that is not a utility name). It covers the
  # whole private-bus session and returns 124 when the limit fired.
  inner=(env AGENT_E2E_PRIVATE_BUS=1 AGENT_E2E_INNER=1 bash "$HERE/run.sh")
  if want_headed; then
    inner=(xvfb-run -a -s "-screen 0 1280x1024x24" "${inner[@]}")
  fi
  rc=0
  run_limited "$limit" 20 "${clean_env[@]}" dbus-run-session --config-file="$RUN_ROOT/bus.conf" -- "${inner[@]}" || rc=$?
  if (( rc == 124 )); then echo "agent E2E: overall limit of ${limit}s reached; the run was stopped" >&2; fi
  node lib/guard.js verify "$snap" || rc=1
  node lib/report.js "$AGENT_E2E_RESULTS" || rc=1
  exit "$rc"
fi

# ---- inner phase: private bus, scrubbed env (and Xvfb when headed) ----
# Defensive: never run a scenario on the session bus the run was started with, a per-user bus socket or no bus.
if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" || "$DBUS_SESSION_BUS_ADDRESS" == "${AGENT_E2E_REAL_BUS:-__none__}" \
  || "$DBUS_SESSION_BUS_ADDRESS" == */run/user/* || "$DBUS_SESSION_BUS_ADDRESS" == *nonexistent* ]]; then
  echo "refusing to run: DBUS_SESSION_BUS_ADDRESS is not a private bus (${DBUS_SESSION_BUS_ADDRESS:-unset})" >&2
  exit 2
fi
node lib/preflight.js || exit 1
exec node --test --test-concurrency=1 --test-reporter=spec scenarios/*.test.js smoke/*.test.js
