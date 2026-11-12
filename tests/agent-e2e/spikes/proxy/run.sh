#!/usr/bin/env bash
# Run one spike script hermetically: private session bus + private X server, fresh HOME per browser launch.
# usage: ./run.sh q1-proxy-basic.js   (ONLY=chromium:headed to restrict; KEEP=1 to keep profiles)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export SPIKE_TMP="${SPIKE_TMP:-$(mktemp -d "${TMPDIR:-/tmp}/passless-proxy-spike-XXXXXX")}"
trap '[ -n "${KEEP:-}" ] || rm -rf "$SPIKE_TMP"' EXIT
dbus-run-session -- xvfb-run -a -s '-screen 0 1280x800x24' node "$here/$1"
