# ADR 0011: seccomp-BPF scope — isolated mode only, principal-first, browser deferred

- **Status:** Accepted
- **Date:** 2026-08-27
- **Decision owners:** Passless maintainers
- **Related decisions:** [ADR 0008](0008-same-user-trust-boundary.md), [ADR 0009](0009-daemon-hardening-scope.md), [ADR 0010](0010-namespace-isolation-scope.md)
- **Affects:** security analysis item H-3 in [FURTHER_ANALYSIS.md](../security/FURTHER_ANALYSIS.md)

## Context

H-3 documents that no seccomp-BPF filter is applied to any spawned process. Ground-truth
review (2026-08) confirmed:

- No seccomp setup exists anywhere; `PR_SET_NO_NEW_PRIVS` is the only syscall-adjacent
  restriction on children. No seccomp/libseccomp crate is vendored; all hardening uses
  raw `libc`.
- The agent passes no sandbox-related flags to Chromium. Chromium applies its own
  internal seccomp sandbox to renderer/GPU processes; the gap concerns the browser
  *chrome* process and our *principal* process.
- No syscall profiling has ever been performed; the required syscall surface for either
  child type is undocumented.

## Decision

1. **H-3 is out of scope for same-user mode.** Per ADR 0008 the browser is inside the
   user's trust boundary; a same-UID peer can ptrace the daemon, so restricting the
   child's syscall set does not raise the boundary — and wrapper setup risks breaking
   Chromium.

2. **Isolated (cross-user) mode only**, split by risk into two backlog items:
   - **H-3a — principal process seccomp (early, feasible).** The principal is our own
     binary with a controlled syscall surface. Blacklist-first (e.g. ptrace, mount,
     bpf, init_module, kexec_load, perf_event_open) is maintainable and low-risk.
     Implement alongside the isolated-mode hardening work (ADRs 0009/0010).
   - **H-3b — browser chrome process seccomp (deferred).** Chromium sandbox
     initialization is version-dependent; even a blacklist can break startup on some
     versions. Deferred to the same wave as the mount-namespace work (ADR 0010) and
     requires syscall profiling first per Chromium version.

## Consequences

- H-3 remains open but re-scoped: isolated-mode only, principal-first.
- Same-user mode has no seccomp action items (closed by ADR 0008).
- Chromium renderer/GPU seccomp remains Chromium's responsibility (already present); no
  change needed there.

## References

- `cmd/passless/src/agent/launcher.rs` `HardenedChildSetup::apply`
- `cmd/passless/src/agent/browser.rs` `build_browser_command` (no sandbox flags passed)
- [FURTHER_ANALYSIS.md](../security/FURTHER_ANALYSIS.md) H-3 and risks section
- [ADR 0009](0009-daemon-hardening-scope.md) — companion backlog for the daemon unit
- [ADR 0010](0010-namespace-isolation-scope.md) — companion namespace backlog
