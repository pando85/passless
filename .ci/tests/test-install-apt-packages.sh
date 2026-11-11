#!/usr/bin/env bash
# Tests for .ci/install-apt-packages.sh
#
# Stubs sudo, apt-get and sleep so the script can be exercised without root or
# network access. Verifies:
#   - missing arguments exit with usage error
#   - success on the first attempt does not retry
#   - transient failures trigger retries and eventually succeed
#   - persistent failures exit non-zero after exhausting all attempts
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT_DIR/.ci/install-apt-packages.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

stub_dir="$tmp/stubs"
mkdir -p "$stub_dir"

cat >"$stub_dir/sudo" <<'EOF'
#!/usr/bin/env bash
exec "$@"
EOF
chmod +x "$stub_dir/sudo"

cat >"$stub_dir/sleep" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SLEEP_LOG"
EOF
chmod +x "$stub_dir/sleep"

cat >"$stub_dir/apt-get" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$APT_LOG"
state_dir="$STUB_STATE"
count_file="$state_dir/attempts"
count=0
if [[ -f "$count_file" ]]; then
    count=$(<"$count_file")
fi
count=$((count + 1))
printf '%s\n' "$count" >"$count_file"
fail_first="${FAIL_FIRST:-0}"
if (( count <= fail_first )); then
    exit 100
fi
exit 0
EOF
chmod +x "$stub_dir/apt-get"

pass=0
fail=0

run_test() {
    local name="$1"
    shift
    if "$@"; then
        printf 'PASS  %s\n' "$name"
        (( pass++ )) || true
    else
        printf 'FAIL  %s\n' "$name"
        (( fail++ )) || true
    fi
}

assert_eq() {
    local actual="$1" expected="$2" label="$3"
    if [[ "$actual" == "$expected" ]]; then
        return 0
    fi
    printf '  %s: expected %q, got %q\n' "$label" "$expected" "$actual"
    return 1
}

# --- Test 1: no packages → usage error ---
test_usage_error() {
    local state_dir="$tmp/state-1"
    mkdir -p "$state_dir"
    local apt_log="$tmp/apt-1.log"
    local sleep_log="$tmp/sleep-1.log"
    : >"$apt_log"; : >"$sleep_log"

    local rc=0
    STUB_STATE="$state_dir" APT_LOG="$apt_log" SLEEP_LOG="$sleep_log" \
        PATH="$stub_dir:$PATH" \
        bash "$SCRIPT" >/dev/null 2>/dev/null || rc=$?

    assert_eq "$rc" 2 "exit code" &&
        assert_eq "$(wc -l <"$apt_log")" 0 "apt-get invocations"
}
run_test "no packages → usage error" test_usage_error

# --- Test 2: success on first attempt, no retries ---
test_first_try_success() {
    local state_dir="$tmp/state-2"
    mkdir -p "$state_dir"
    local apt_log="$tmp/apt-2.log"
    local sleep_log="$tmp/sleep-2.log"
    : >"$apt_log"; : >"$sleep_log"

    local rc=0
    FAIL_FIRST=0 STUB_STATE="$state_dir" APT_LOG="$apt_log" SLEEP_LOG="$sleep_log" \
        PATH="$stub_dir:$PATH" \
        bash "$SCRIPT" pkg-a pkg-b >/dev/null 2>/dev/null || rc=$?

    local apt_lines sleep_lines
    apt_lines=$(wc -l <"$apt_log")
    sleep_lines=$(wc -l <"$sleep_log")

    assert_eq "$rc" 0 "exit code" &&
        assert_eq "$apt_lines" 2 "apt-get invocations (update + install)" &&
        assert_eq "$sleep_lines" 0 "sleep invocations" &&
        grep -q '^update$' "$apt_log" &&
        grep -q '^install -y -- pkg-a pkg-b$' "$apt_log"
}
run_test "success on first attempt" test_first_try_success

# --- Test 3: transient failure, succeeds on retry ---
test_transient_failure() {
    local state_dir="$tmp/state-3"
    mkdir -p "$state_dir"
    local apt_log="$tmp/apt-3.log"
    local sleep_log="$tmp/sleep-3.log"
    : >"$apt_log"; : >"$sleep_log"

    # First apt-get call (update) fails; subsequent calls succeed.
    local rc=0
    FAIL_FIRST=1 STUB_STATE="$state_dir" APT_LOG="$apt_log" SLEEP_LOG="$sleep_log" \
        PATH="$stub_dir:$PATH" \
        bash "$SCRIPT" pkg-a >/dev/null 2>/dev/null || rc=$?

    local apt_lines sleep_lines
    apt_lines=$(wc -l <"$apt_log")
    sleep_lines=$(wc -l <"$sleep_log")

    assert_eq "$rc" 0 "exit code" &&
        assert_eq "$apt_lines" 3 "apt-get invocations (update-fail, update, install)" &&
        assert_eq "$sleep_lines" 1 "sleep invocations" &&
        grep -q '10' "$sleep_log"
}
run_test "transient failure, succeeds on retry" test_transient_failure

# --- Test 4: persistent failure → non-zero exit ---
test_persistent_failure() {
    local state_dir="$tmp/state-4"
    mkdir -p "$state_dir"
    local apt_log="$tmp/apt-4.log"
    local sleep_log="$tmp/sleep-4.log"
    : >"$apt_log"; : >"$sleep_log"

    # All apt-get calls fail (high fail count).
    local rc=0
    FAIL_FIRST=999 STUB_STATE="$state_dir" APT_LOG="$apt_log" SLEEP_LOG="$sleep_log" \
        PATH="$stub_dir:$PATH" \
        bash "$SCRIPT" pkg-a >/dev/null 2>/dev/null || rc=$?

    local apt_lines sleep_lines
    apt_lines=$(wc -l <"$apt_log")
    sleep_lines=$(wc -l <"$sleep_log")

    (( rc != 0 )) &&
        assert_eq "$apt_lines" 3 "apt-get invocations (3 update attempts)" &&
        assert_eq "$sleep_lines" 2 "sleep invocations (between attempts)"
}
run_test "persistent failure → non-zero exit" test_persistent_failure

printf '\n%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
