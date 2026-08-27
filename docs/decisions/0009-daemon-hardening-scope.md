# ADR 0009: Daemon hardening scope — root multi-principal deployments only

- **Status:** Accepted
- **Date:** 2026-08-27
- **Decision owners:** Passless maintainers
- **Related decisions:** [ADR 0008](0008-same-user-trust-boundary.md), [ADR 0007](0007-unified-agent-identity-modes.md)
- **Affects:** security analysis item C-2 in [FURTHER_ANALYSIS.md](../security/FURTHER_ANALYSIS.md)

## Context

C-2 documents that the root system unit (`passless-agent.service`) runs with
`NoNewPrivileges=false`, `PrivateDevices=false`, and lacks ~11 systemd hardening
directives. Ground-truth review (2026-08) clarified the deployment reality:

- Two units exist. The system unit (`passless-agent.service`) runs as root for
  cross-user principal/browser spawning; the user unit (`passless.service`) runs
  unprivileged as the logged-in user.
- Root is needed **continuously**, not only at startup: every cross-user spawn
  performs `setuid`/`setgid` in the child (`launcher.rs` `HardenedChildSetup::apply`),
  which is precisely why `NoNewPrivileges=false`. No capability-dropping code exists.
- `PrivateDevices=false` is required: Chromium enumerates dynamically-created hidraw
  nodes, so a static device namespace cannot work.

The meaningful question is therefore not "should the daemon be less privileged" in the
abstract, but **which deployment mode C-2 applies to**. In same-user mode (ADR 0008), the
daemon is unprivileged and the browser shares the user's UID — no OS boundary exists or
is attempted, and the user unit's weak systemd hardening score is a non-issue.

## Decision

1. **C-2 is in-scope only for the root multi-principal (cross-user isolation)
   deployment mode.** This mode provides real isolation between the agent and the user
   and therefore warrants maximal defense-in-depth for the root daemon.

2. **For same-user deployments**, C-2 does not apply (covered by ADR 0008). The user
   unit's `systemd-analyze security` score (9.4 UNSAFE) is accepted as the mode's intent
   — the daemon has no more privilege than the session it serves.

3. **Hardening work is deferred for later implementation**, recorded here as the
   roadmap for the root deployment:

   - **C-2a — freely additive directives** (no code risk, implement when the root mode
     is deployed): `ProtectHostname=true`, `ProtectClock=true`,
     `ProtectKernelLogs=true`, `LockPersonality=true`, `RestrictRealtime=true`,
     `RestrictAddressFamilies=AF_UNIX` (+ `AF_INET AF_INET6` only if networking is
     needed by the deployment).
   - **C-2b — evaluated directives**: `RestrictNamespaces` and `MemoryDenyWriteExecute`
     (must be tested against browser spawn / JIT), and the high-value pair
     `CapabilityBoundingSet` (bound to the minimal set the daemon needs, e.g.
     CAP_SETUID/CAP_SETGID + device access) and `SystemCallFilter` (requires syscall
     profiling first).

4. **Open design problem deferred:** whether the daemon can operate with a bounded
   capability set instead of full root (capability dropping post-startup, or a small
   privileged helper for setuid spawn and UHID creation). Deferred because it requires
   an isolation-mode redesign, not a unit-file change.

## Consequences

- C-2 stays open in FURTHER_ANALYSIS.md but is re-scoped: it tracks hardening of the
  **root multi-principal** deployment only.
- No code or unit-file changes now; the additive list (C-2a) and evaluation list (C-2b)
  are the implementation backlog for when the isolated mode is productionized.
- Same-user deployments have no C-2 action items.

## References

- `contrib/systemd/passless-agent.service` (system/root unit)
- `contrib/systemd/passless.service` (user unit)
- `cmd/passless/src/agent/launcher.rs` `HardenedChildSetup::apply` (setuid in child)
- [ADR 0008](0008-same-user-trust-boundary.md) — same-user trust boundary
- [FURTHER_ANALYSIS.md](../security/FURTHER_ANALYSIS.md) C-2
