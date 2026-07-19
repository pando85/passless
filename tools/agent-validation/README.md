# Agent Validation Orchestrator

This directory contains the fail-closed release-lab orchestrator specified in `docs/plans/agent-adr-validation-closure.md`.

## Overview

The agent validation orchestrator provides a fail-closed framework to run comprehensive tests on the Passless agent implementation. It implements the validation architecture with three tiers:

- **Tier 1**: Deterministic automated tests (unit, integration, policy, protocol, etc.)
- **Tier 2**: Automated browser session tests (Chromium, notifications, ceremonies)
- **Tier 3**: Privileged release lab tests (device permissions, principal isolation)

## Requirements

- x86_64 Linux environment (for release mode)
- Rust/Cargo toolchain
- systemd, udev, cgroup v2 (for release mode)
- UHID kernel module
- Chromium browser (for Tier 2)
- Node.js 22+, Xvfb, dunst, and dunstctl (for Tier 2)
- pass, GPG, and swtpm (for backend composition)
- Disposable agent/human users, profiles, and credential stores (for Tier 3)

## Usage

### Commands

```bash
# Run preflight checks only
tools/agent-validation/run.sh --preflight

# Run automated tests (Tier 1 and Tier 2)
tools/agent-validation/run.sh --automated

# Run full release validation (Tier 1, Tier 2, and Tier 3)
tools/agent-validation/run.sh --release

# Explicitly permit a dirty lab worktree (recorded in environment.json)
tools/agent-validation/run.sh --release --allow-dirty

# Clean up resources from a specific run
tools/agent-validation/run.sh --cleanup <run-id>

# Explicitly delete preserved evidence
tools/agent-validation/run.sh --delete-evidence <run-id>

# Run the non-privileged deterministic subset used by CI
make test-agent-validation
```

### Options

- `--preflight`: Run capability-based preflight checks only
- `--automated`: Run automated tests (Tier 1 and Tier 2)
- `--release`: Run full release validation (requires explicit confirmation for privileged operations)
- `--allow-dirty`: Permit a dirty worktree for release recovery; never implied
- `--cleanup <run-id>`: Clean registered host resources while preserving evidence
- `--delete-evidence <run-id>`: Delete a run after typing `DELETE`
- `--help`: Show usage information

### Environment Variables

- `RUN_ID_PREFIX`: Prefix for the run ID (default: agent-validation)
- `EVIDENCE_BASE_DIR`: Base directory for evidence (default: target/agent-validation)

Live browser and privileged stages require explicit `AV_*` variables for disposable profile IDs, users, runtime roots, stores, and binaries. The stage scripts reject missing or unsafe values; see their header comments for the exact variables.

## Evidence and Reports

Test evidence is stored in `target/agent-validation/<run-id>/` with `0700` permissions:

- `orchestrator.log`: Complete execution log
- `environment.json`: System environment manifest
- `report.json`: Machine-readable test results
- `report.md`: Human-readable summary report

Reports distinguish between:
- `PASS`: Test completed successfully
- `FAIL`: Test failed
- `SKIP`: Required environment or live evidence was unavailable

## Safety Features

- Fail-closed by design
- Host resource cleanup only (preserves evidence)
- Safe path/ownership validation with canonical path enforcement
- Strict data format parsing (no unsafe sourcing)
- Narrowly scoped privileged helper mechanism
- Never runs whole orchestrator as root
- No raw secrets in evidence
- Explicit validation of required stages

## Completion Semantics

All wired stages either run their asserted behavior or report `SKIP`. A required skip makes the run `INCOMPLETE` with a nonzero exit. Dry-run output and command availability never count as live evidence.

`make test-agent-validation` is the CI-safe deterministic subset. Engineering closure additionally requires one complete `--release` run on the recorded x86_64 lab. Independent security review remains a separate ADR release gate.

## Integration Points

This orchestrator integrates with:
- Existing fmt/clippy/test pipelines
- Phase 0 tooling
- The broader agent validation plan
