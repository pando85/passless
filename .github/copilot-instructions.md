# Repository Copilot Instructions (passless-cli)

High-signal, low-noise playbook. Assume reader is experienced; omit trivia.

## Project Overview

Rust 2024 single-binary CLI countdown/alarm: FIGLET big output, optional loop, sound + PC speaker
beep, terminal bell. Targets Linux & macOS (beep gracefully no-op off Linux). Goal: instant start,
minimal deps, stable UX, safe terminal restore.

## Tech Stack

Core crates: `clap`, `crossterm`, `time`, `regex`, `rodio(vorbis)`, `nix`+`libc` (beep), `tailcall`.
Heavy work amortized via `LazyLock` (FIGLET + device discovery). Clippy warnings = errors.

## Layout

Root: `Cargo.toml`, `Makefile`, `README.md`, `CHANGELOG.md`, `PERMISSIONS.md`, CI workflows under
`.github/workflows/`.

Src modules:

- `main.rs` entry + signal handling
- `opts.rs` CLI (`Opts`)
- `passless.rs` countdown loop (tail-recursive), parsing, alarm triggers
- `time.rs` convert + FIGLET render + centering fallback
- `ui.rs` terminal setup/draw/restore
- `beep.rs` PC speaker selection + ioctl/evdev
- `sound/` rodio abstraction
- `constants.rs` timing + limits
- `utils.rs` `spawn_thread` + `JoinWithTimeout`
- `figlet/` font + renderer
- Tests live inline via `#[cfg(test)]`.

## Build & Run

Bootstrap (Linux): install Rust stable + `libasound2-dev`. Optional: `pre-commit install`. Preferred
workflow: `make fmt` → `make clippy` → `make test` → `cargo run -- -s 10`. Release: `make release`
(produces tar + `vendor.tar.gz`). Publish: `make publish` (needs `CRATES_IO_TOKEN`). Common runs:

- `cargo run -- -s 2m`
- `cargo run -- -t -s 1m30s`
- `cargo run -- --loop -s 5s`

## CI Summary

`rust.yml`: fmt, clippy, build+test matrix (macOS + Ubuntu 22.04), package, optional publish/tag
release. `auto-tag.yaml`: signs tag from `CHANGELOG.md`. `aur-publish.yml`: builds Arch PKGBUILDs
post successful release run. `pre-commit.yml`: runs hooks (Rust lint handled elsewhere).

## Coding & Performance Rules

Always format + lint before tests. Preserve tail recursion in `countdown`. No new `unsafe` outside
`beep.rs`. Keep 1Hz loop lean: no extra allocations/logging. Batch terminal ops with `execute!`.
Favor explicit error handling; silent degradation for beep device absence.

## Parsing Logic

`parse_counter_time`: patterns like `2h10m`, `1m10s`, `5m120s`, `19min3s`, bare seconds (`350`),
`5m50` (minutes + implicit seconds). Reject clock formats here. `parse_end_time`: `H:MM`, `HH:MM`,
`HH:MM:SS`, `HH:MM:SS.millis`; wraps to next day if time already passed. Add new grammar → add
tests; avoid regex proliferation (single compiled set).

## Audio / Alert

Beep path discovery once (`LazyLock`). If no device writable: silent fallback (no crash). Sound +
beep run in parallel: sound on thread (with timeout), synchronous beep loop respects constants.
Adjusting constants? Recalculate `PLAY_TIMEOUT` relationship.

## Extensibility

Safe additions: new CLI flag (update `opts.rs`, plumb through `main`, add tests), alternate render
mode (new enum + branch in `ui`), new post-alarm action (after zero draw, before exit / loop). Keep
terminal restore semantics first on exit paths. Avoid async runtimes, global mutable state,
long-lived threads beyond countdown + ephemeral alarm.

## Testing Targets

Add tests for new parse variants, FIGLET fallback (simulate tiny term by forcing non-centered path),
rounding boundaries (<1s, ms to s). Do not attempt real audio/beep in CI.

## Error & Signal Safety

Always call `ui::restore_terminal` on early exit or error. Signal handler minimal: redraw on
`SIGWINCH`, restore + exit on INT/TERM/QUIT. No panics inside handler.

## Release & Distribution

Tagging auto from `CHANGELOG.md`; keep top entry accurate pre-tag. AUR flow depends on
`.ci/generate-pkgbuild.rh`. `vendor.tar.gz` created in release for reproducibility.

## Dependency Hygiene

Justify any new crate: size / security / compile time. Use narrow feature sets. Run `cargo tree -d`
after adding. Avoid adding heavy proc-macros casually.

## Pitfalls

- Missing `libasound2-dev` → rodio build fail.
- Adding prints per tick → flicker/perf drop.
- Not threading new CLI fields through loop spawn in `main` → inconsistent behavior.
- Changing timing constants without adjusting `PLAY_TIMEOUT` → clipped audio.
- Regex bloat → slower parse; keep single set.

## Agent Guidance

Trust this file; search only if info absent or build/test fails. Maintain zero clippy warnings.
Prefer minimal diffs + tests. No network I/O or timezone hacks. Preserve terminal integrity and
countdown accuracy above micro-optimizations. Tail recursion stays unless broken.

## Quick Commands

- Format: `make fmt`
- Lint: `make clippy`
- Test: `make test`
- Run sample: `cargo run -- -s 25`
- Loop sample: `cargo run -- --loop -s 10s`
- Release: `make release`

## When Unsure

If change touches signals, terminal restore, or alarm timing: flag for review. Pure additive &
tested: proceed.

End.
