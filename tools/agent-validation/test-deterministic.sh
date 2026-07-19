#!/bin/bash

set -euo pipefail
set -x

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}"

for forbidden_var in PASSLESS_E2E_AUTO_ACCEPT_UV PASSLESS_E2E_AUTO_ACCEPT_STORAGE; do
    if [[ -n "${!forbidden_var+x}" ]]; then
        printf 'Refusing validation with %s set\n' "$forbidden_var" >&2
        exit 1
    fi
done

for required_tool in dbus-daemon gpg jq node pass shellcheck swtpm; do
    if ! command -v "$required_tool" >/dev/null; then
        printf 'Missing deterministic validation dependency: %s\n' "$required_tool" >&2
        exit 1
    fi
done

echo "=== Phase 1: shellcheck ===" >&2
shellcheck -S warning \
    tools/agent-validation/run.sh \
    tools/agent-validation/validate \
    tools/agent-validation/lib/*.sh \
    tools/agent-validation/stages/*.sh \
    tools/agent-validation/browser/*.sh \
    tools/agent-validation/tests/*.sh \
    tools/agent-validation/test-orchestrator.sh

shell_tests=(
    tools/agent-validation/test-orchestrator.sh
    tools/agent-validation/tests/test-tier2-stages.sh
    tools/agent-validation/tests/test-real-notifications.sh
    tools/agent-validation/tests/test-privilege-helper.sh
    tools/agent-validation/tests/test-principal-checks.sh
    tools/agent-validation/tests/test-device-matrix.sh
    tools/agent-validation/tests/test-tier3-stages.sh
    tools/agent-validation/tests/test-uninstall-rehearsal.sh
    tools/agent-validation/tests/test-fault-injection.sh
    tools/agent-validation/tests/test-secret-scanning.sh
)

echo "=== Phase 2: shell tests ===" >&2
for test_script in "${shell_tests[@]}"; do
    echo "--- Running: $test_script ---" >&2
    timeout 300s bash "$test_script"
done

echo "=== Phase 3: cargo test (parallel) ===" >&2
timeout 600s cargo test --all-features -- \
    --skip agent::prompt::dbus_tests \
    --skip ceremony_observer \
    --skip agent::storage_factory::tests::composition_conformance \
    --skip agent::browser::tests::test_cdp_pipes_drop_closes_fds \
    --skip agent::browser::tests::test_child_in_separate_process_group \
    --skip agent::browser::tests::test_no_fd_leakage_to_child \
    --skip agent::browser::tests::test_concurrent_launch_and_revoke \
    --skip agent::browser::tests::test_manager_cleanup_detects_inode_change \
    --skip agent::runtime::tests \
    --skip agent::launcher::tests::test_spawn_principal_non_root_fails_closed \
    --skip commands::agent_admin::tests::auto_fails_when_no_agent_detected

echo "=== Phase 4: cargo test (agent-principal-probe) ===" >&2
timeout 300s cargo test -p agent-principal-probe

echo "=== Phase 5: cargo test (dbus, single-threaded) ===" >&2
timeout 300s cargo test --all-features -p passless-rs --bin passless \
    agent::prompt::dbus_tests -- --test-threads=1

echo "=== Phase 6: cargo test (ceremony_observer, single-threaded) ===" >&2
timeout 300s cargo test --all-features -p passless-rs --bin passless \
    ceremony_observer -- --test-threads=1

echo "=== Phase 7: cargo test (composition_conformance, single-threaded) ===" >&2
timeout 600s cargo test --all-features -p passless-rs --bin passless \
    agent::storage_factory::tests::composition_conformance -- \
    --include-ignored --test-threads=1

echo "=== Phase 8: cargo test (browser FD tests, single-threaded) ===" >&2
timeout 120s cargo test --all-features -p passless-rs --bin passless \
    agent::browser::tests::test_cdp_pipes_drop_closes_fds -- --test-threads=1
timeout 120s cargo test --all-features -p passless-rs --bin passless \
    agent::browser::tests::test_child_in_separate_process_group -- --test-threads=1
timeout 120s cargo test --all-features -p passless-rs --bin passless \
    agent::browser::tests::test_no_fd_leakage_to_child -- --test-threads=1
timeout 120s cargo test --all-features -p passless-rs --bin passless \
    agent::browser::tests::test_concurrent_launch_and_revoke -- --test-threads=1
timeout 120s cargo test --all-features -p passless-rs --bin passless \
    agent::browser::tests::test_manager_cleanup_detects_inode_change -- --test-threads=1

echo "=== Phase 9: cargo test (runtime tests, single-threaded) ===" >&2
timeout 600s cargo test --all-features -p passless-rs --bin passless \
    agent::runtime::tests -- --test-threads=1

echo "=== Phase 10: cargo test (launcher tests, single-threaded) ===" >&2
timeout 120s cargo test --all-features -p passless-rs --bin passless \
    agent::launcher::tests::test_spawn_principal_non_root_fails_closed -- --test-threads=1

echo "=== Phase 10b: cargo test (agent_admin tests, single-threaded) ===" >&2
timeout 120s cargo test --all-features -p passless-rs --bin passless \
    commands::agent_admin::tests::auto_fails_when_no_agent_detected -- --test-threads=1

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/passless-agent-validation.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/tmp"
chmod 700 "$tmp_dir" "$tmp_dir/tmp"
export EVIDENCE_DIR="$tmp_dir"
export TEMP_ROOT="$tmp_dir/tmp"
export AV_VALIDATION_DIR="$ROOT_DIR/tools/agent-validation"

# shellcheck source=tools/agent-validation/lib/common.sh
source tools/agent-validation/lib/common.sh
# shellcheck source=tools/agent-validation/lib/fault-injection.sh
source tools/agent-validation/lib/fault-injection.sh
# shellcheck source=tools/agent-validation/stages/fault-injection.sh
source tools/agent-validation/stages/fault-injection.sh
# shellcheck source=tools/agent-validation/lib/secret-scanning.sh
source tools/agent-validation/lib/secret-scanning.sh
# shellcheck source=tools/agent-validation/stages/secret-scanning.sh
source tools/agent-validation/stages/secret-scanning.sh

echo "=== Phase 11: fault injection ===" >&2
stage_fault_injection

echo "=== Phase 12: secret scanning ===" >&2
stage_secret_scanning

echo "=== All phases completed ===" >&2
