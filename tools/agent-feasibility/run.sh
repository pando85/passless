#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NODE_PATH="${NODE_PATH:-$(npm root -g)}"

if [[ -z "${DISPLAY:-}" ]]; then
  exec xvfb-run -a node "$root/probe.js"
fi

exec node "$root/probe.js"
