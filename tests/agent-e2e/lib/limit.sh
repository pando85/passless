# shellcheck shell=bash
# Overall run limit for the agent E2E runner (sourced by run.sh).
#
# Why not `timeout`: a bare `timeout` process is matched by any `pkill -x timeout` (another shell, another agent
# session on this machine). It forwards SIGTERM to the whole run's process group and node:test then reports
# "Interrupted" and cancels every remaining scenario file. Running the coreutils binary under another name is no
# fix either: uutils coreutils (the ubuntu-26.04 default) is a multicall binary that refuses to run when its
# argv[0] is not a utility name ("Security violation: Requested utility ... does not match executable name").
# So the limit is a watchdog made of shell builtins only: no external process whose name could be matched, and
# nothing that depends on which coreutils implementation is installed.
#
#   run_limited SECONDS GRACE COMMAND [ARG...]
#
# Runs COMMAND in a process group of its own. When SECONDS elapse the group gets SIGTERM; if any member is still
# alive GRACE seconds later it gets SIGKILL (the `timeout -k GRACE SECONDS` behaviour). Returns 124 when the
# limit fired, otherwise COMMAND's exit status. A SIGINT/SIGTERM/SIGHUP received by the caller is forwarded to the
# group as SIGTERM, and if the caller itself is killed the watchdog stops the run as well, so a run never
# outlives its runner. Bash 4+.

# True while any member of process group $1 is alive.
_limit_group_alive() { kill -0 -- "-$1" 2>/dev/null; }

# Sleep for $1 seconds (fractions allowed) with a builtin: a read with a timeout on a descriptor that never
# delivers data, so the watchdog has no `sleep` to be killed by name either. Needs fd 8 (see _limit_watchdog).
_limit_nap() { read -r -t "$1" -u 8 || true; }

# Watchdog body (runs as a background subshell): $1 = group leader pid, $2 = limit, $3 = grace, $4 = runner pid,
# $5 = marker file created when the limit fires. Exits 0 when the run ends first, 124 after it fired.
_limit_watchdog() {
  local pid=$1 limit=$2 grace=$3 runner=$4 marker=$5 deadline
  exec 8<> <(:)
  deadline=$((SECONDS + limit))
  while (( SECONDS < deadline )); do
    _limit_nap 1
    _limit_group_alive "$pid" || return 0
    # The runner was killed outright (no chance to clean up): do not leave the run behind unbounded.
    kill -0 "$runner" 2>/dev/null || break
  done
  _limit_group_alive "$pid" || return 0
  : > "$marker"
  kill -TERM -- "-$pid" 2>/dev/null || true
  deadline=$((SECONDS + grace))
  while _limit_group_alive "$pid" && (( SECONDS < deadline )); do _limit_nap 0.2; done
  kill -KILL -- "-$pid" 2>/dev/null || true
  return 124
}

run_limited() {
  local limit=$1 grace=$2 pid wd marker rc=0
  shift 2
  [[ $limit =~ ^[0-9]+$ && $grace =~ ^[0-9]+$ ]] || { echo "run_limited: SECONDS and GRACE must be integers" >&2; return 2; }
  marker="$(mktemp -u "${TMPDIR:-/tmp}/agent-e2e-limit.XXXXXX")" || return 2

  # Job control gives the background job its own process group (pgid == pid) that the watchdog can signal as a
  # unit. It is enabled only around the launch.
  set -m
  "$@" &
  pid=$!
  set +m
  _limit_watchdog "$pid" "$limit" "$grace" "$$" "$marker" &
  wd=$!

  # shellcheck disable=SC2064 # $pid is expanded now, on purpose
  trap "kill -TERM -- -$pid 2>/dev/null || true" INT TERM HUP
  wait "$pid" || rc=$?
  # `wait` returns early when a trapped signal arrives; keep waiting for the real exit status.
  while kill -0 "$pid" 2>/dev/null; do wait "$pid" || rc=$?; done
  trap - INT TERM HUP

  if [[ -e $marker ]]; then
    # The limit fired: let the watchdog finish its TERM -> KILL escalation for stragglers (bounded by GRACE).
    wait "$wd" 2>/dev/null || true
    rc=124
  else
    kill "$wd" 2>/dev/null || true
    wait "$wd" 2>/dev/null || true
  fi
  rm -f "$marker"
  return "$rc"
}
