#!/bin/bash
#
# Regression: nothing the deterministic validation runs may use the session bus it inherits.
#
# A private, minimal dbus-daemon plays the developer's "real" session bus. A notify-double owns
# org.freedesktop.Notifications on it and logs every call. The notification-related unit tests, the
# real-notifications stage tests and the stage itself (with a mock dbus-run-session that would run
# the driver on the inherited bus) all start with DBUS_SESSION_BUS_ADDRESS pointing at it; the
# double must see no call at all (no Notify, and no capability probe either). A control call at the
# end proves the double does see traffic.
#
# Never touches the real session bus: it only ever uses the address of the bus it started itself.
#

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
[[ "$TARGET_DIR" == /* ]] || TARGET_DIR="$ROOT_DIR/$TARGET_DIR"

for tool in dbus-daemon dbus-send jq cargo; do
    if ! command -v "$tool" >/dev/null; then
        printf 'test-session-bus-isolation: missing tool: %s\n' "$tool" >&2
        exit 1
    fi
done

WORK_DIR="$(mktemp -d /tmp/passless-bus-canary-XXXXXX)"
DAEMON_PID=""
DOUBLE_PID=""

cleanup() {
    [[ -n "$DOUBLE_PID" ]] && kill "$DOUBLE_PID" 2>/dev/null || true
    [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID" 2>/dev/null || true
    [[ -n "$DOUBLE_PID" ]] && wait "$DOUBLE_PID" 2>/dev/null || true
    [[ -n "$DAEMON_PID" ]] && wait "$DAEMON_PID" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

fail() {
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

log() {
    printf '[TEST] %s\n' "$*" >&2
}

log "building notify-double and the prompt probe"
cargo build --quiet --all-features -p notify-double --bin notify-double
cargo build --quiet --all-features -p passless-rs --bin agent-prompt-probe
DOUBLE_BIN="${TARGET_DIR}/debug/notify-double"
PROBE_BIN="${TARGET_DIR}/debug/agent-prompt-probe"
[[ -x "$DOUBLE_BIN" ]] || fail "no notify-double at $DOUBLE_BIN"
[[ -x "$PROBE_BIN" ]] || fail "no agent-prompt-probe at $PROBE_BIN"

cat > "$WORK_DIR/bus.conf" << CONF
<busconfig>
<type>session</type>
<listen>unix:path=$WORK_DIR/bus.sock</listen>
<auth>EXTERNAL</auth>
<policy context="default">
<allow send_destination="*" eavesdrop="true"/>
<allow eavesdrop="true"/>
<allow own="*"/>
<allow user="*"/>
</policy>
</busconfig>
CONF

env -i PATH="$PATH" HOME="$WORK_DIR" XDG_RUNTIME_DIR="$WORK_DIR" \
    dbus-daemon --config-file="$WORK_DIR/bus.conf" --nofork --print-address=1 \
    > "$WORK_DIR/address" 2> "$WORK_DIR/daemon.err" &
DAEMON_PID=$!
for _ in $(seq 1 100); do
    [[ -s "$WORK_DIR/address" ]] && break
    sleep 0.1
done
[[ -s "$WORK_DIR/address" ]] || fail "the canary bus did not start: $(cat "$WORK_DIR/daemon.err")"
CANARY_BUS="$(head -n1 "$WORK_DIR/address")"

DBUS_SESSION_BUS_ADDRESS="$CANARY_BUS" "$DOUBLE_BIN" \
    --log "$WORK_DIR/calls.jsonl" --ready-file "$WORK_DIR/ready" --script ignore \
    > "$WORK_DIR/double.out" 2>&1 &
DOUBLE_PID=$!
for _ in $(seq 1 100); do
    [[ -e "$WORK_DIR/ready" ]] && break
    sleep 0.1
done
[[ -e "$WORK_DIR/ready" ]] || fail "the canary notification double did not start: $(cat "$WORK_DIR/double.out")"

calls() {
    if [[ -s "$WORK_DIR/calls.jsonl" ]]; then
        wc -l < "$WORK_DIR/calls.jsonl"
    else
        echo 0
    fi
}

assert_silent() {
    local what="$1" count
    count="$(calls)"
    if [[ "$count" -ne 0 ]]; then
        jq -c '{event, summary}' "$WORK_DIR/calls.jsonl" >&2 || true
        fail "$what reached the inherited session bus ($count call(s))"
    fi
    printf '[PASS] %s left the inherited session bus alone\n' "$what" >&2
}

run_on_canary() {
    env DBUS_SESSION_BUS_ADDRESS="$CANARY_BUS" "$@"
}

log "real-notifications stage tests"
run_on_canary bash tools/agent-validation/tests/test-real-notifications.sh > "$WORK_DIR/rn-tests.log" 2>&1 \
    || { cat "$WORK_DIR/rn-tests.log" >&2; fail "test-real-notifications.sh failed"; }
assert_silent "the real-notifications stage tests"

log "real-notifications stage with a dbus-run-session that keeps the inherited bus"
mkdir -p "$WORK_DIR/mock-bin" "$WORK_DIR/evidence" "$WORK_DIR/tmp"
cat > "$WORK_DIR/mock-bin/dbus-run-session" << 'MOCK'
#!/bin/bash
# Not a private bus: it keeps whatever DBUS_SESSION_BUS_ADDRESS it was started with.
[[ "$1" == "--" ]] && shift
exec "$@"
MOCK
chmod +x "$WORK_DIR/mock-bin/dbus-run-session"
(
    export DBUS_SESSION_BUS_ADDRESS="$CANARY_BUS"
    export PATH="$WORK_DIR/mock-bin:$PATH"
    export EVIDENCE_DIR="$WORK_DIR/evidence" TEMP_ROOT="$WORK_DIR/tmp" RUN_ID="bus-isolation"
    export AV_VALIDATION_DIR="$ROOT_DIR/tools/agent-validation"
    export PASSLESS_PROMPT_PROBE_BIN="$PROBE_BIN"
    # shellcheck source=tools/agent-validation/lib/common.sh
    source "$ROOT_DIR/tools/agent-validation/lib/common.sh"
    # shellcheck source=tools/agent-validation/lib/notifications.sh
    source "$ROOT_DIR/tools/agent-validation/lib/notifications.sh"
    # shellcheck source=tools/agent-validation/stages/real-notifications.sh
    source "$ROOT_DIR/tools/agent-validation/stages/real-notifications.sh"
    register_resource() { :; }
    stage_real_notifications > "$WORK_DIR/stage.log" 2>&1 || true
)
assert_silent "the real-notifications stage"

log "prompt, doctor, runtime and escalation unit tests"
run_on_canary cargo test --quiet --all-features -p passless-rs --bin passless -- \
    agent::doctor agent::prompt agent::escalation agent::runtime > "$WORK_DIR/unit.log" 2>&1 \
    || { tail -n 40 "$WORK_DIR/unit.log" >&2; fail "the unit tests failed"; }
assert_silent "the prompt, doctor, runtime and escalation unit tests"

log "prompt child integration tests"
run_on_canary cargo test --quiet --all-features -p passless-rs --test agent_escalation_prompt \
    > "$WORK_DIR/integration.log" 2>&1 \
    || { tail -n 40 "$WORK_DIR/integration.log" >&2; fail "the prompt child integration tests failed"; }
assert_silent "the prompt child integration tests"

log "control: a Notify sent on purpose is seen by the double"
run_on_canary dbus-send --session --print-reply --dest=org.freedesktop.Notifications \
    /org/freedesktop/Notifications org.freedesktop.Notifications.Notify \
    string:control uint32:0 string: string:control string:control array:string: \
    dict:string:variant: int32:0 > /dev/null
for _ in $(seq 1 50); do
    [[ "$(jq -s '[.[] | select(.event == "Notify")] | length' "$WORK_DIR/calls.jsonl")" -ge 1 ]] && break
    sleep 0.1
done
[[ "$(jq -s '[.[] | select(.event == "Notify")] | length' "$WORK_DIR/calls.jsonl")" -ge 1 ]] \
    || fail "the control Notify was not seen: the canary bus cannot detect a leak"
printf '[PASS] the canary bus sees a deliberate Notify\n' >&2
