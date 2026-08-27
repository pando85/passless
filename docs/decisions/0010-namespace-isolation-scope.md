# ADR 0010: OS namespace isolation scope — isolated mode only, mount-first, pipe-mode preferred

- **Status:** Accepted
- **Date:** 2026-08-27
- **Decision owners:** Passless maintainers
- **Related decisions:** [ADR 0008](0008-same-user-trust-boundary.md), [ADR 0009](0009-daemon-hardening-scope.md), [ADR 0007](0007-unified-agent-identity-modes.md)
- **Affects:** security analysis item H-2 in [FURTHER_ANALYSIS.md](../security/FURTHER_ANALYSIS.md)

## Context

H-2 documents that no Linux namespace isolation is applied to browser or principal
processes. Ground-truth review (2026-08) confirmed:

- No `unshare()` / `clone(CLONE_NEW*)` / `setns()` call exists anywhere. All spawn paths
  (`spawn_browser_hardened`, `spawn_browser_port_mode`, `spawn_principal`) share the
  daemon's mount, PID, network, user, and IPC namespaces.
- `read_namespace_inodes()` only observes namespace inodes to detect a peer migrating
  namespaces mid-session; it enforces nothing.
- The browser inherits the daemon environment wholesale (`DISPLAY`, `WAYLAND_DISPLAY`,
  X11/Wayland sockets, D-Bus); no scrubbing or bind-mount awareness exists.
- Two CDP exposure modes exist: pipe mode (CDP over fds 3/4, no network) and port mode
  (CDP over `127.0.0.1:<port>`, requires shared loopback).
- A naming ambiguity exists: `AgentMode::Isolated` means **credential** isolation
  (separate storage backend), not OS namespace isolation.

## Decision

1. **H-2 is out of scope for same-user mode.** Per ADR 0008, the browser runs in the
   user's session trust boundary. Mount/user namespace games against a same-UID,
   ptrace-capable peer offer no commensurate security for the usability cost
   (fonts/themes/D-Bus/Wayland fragmentation).

2. **H-2 is in scope for the isolated (cross-user) deployment mode only**, deferred
   together with C-2 (ADR 0009) until that mode is productionized. Order of work when
   picked up:
   - **Mount namespace first** — hide other principals' storage and daemon-only paths
     from the browser/principal, with a configurable bind-mount allowlist
     (profile dir, runtime dir, X11/Wayland socket, fonts, themes).
   - **PID namespace** as a stretch goal.
   - **Network namespace only in pipe mode.** Port mode is documented as incompatible
     with network isolation (CDP discovery requires shared loopback).

3. **Terminology disambiguation:** `AgentMode::Isolated` continues to mean
   credential/storage isolation. Any future OS namespace hardening is a separate layer
   and must not be implied by the mode name. Documentation should avoid conflating the
   two.

4. **Implementation notes for later:** `nix` is already a dependency but needs the
   `sched` (unshare, CloneFlags) and `mount` features enabled; no bubblewrap/landlock
   crates are vendored.

## Consequences

- H-2 remains open but re-scoped: an implementation backlog item for isolated mode only.
- Same-user mode has no namespace action items (closed by ADR 0008).
- Doc/terminology hygiene: future docs must not conflate credential `Isolated` with OS
  namespace isolation.

## References

- `cmd/passless/src/agent/browser.rs` spawn paths; `launcher.rs` `HardenedChildSetup::apply`
- `cmd/passless/src/agent/launcher.rs` `read_namespace_inodes` (verification-only)
- `passless-core/src/agent/config.rs` `AgentMode::Isolated`, `CdpExposeMode::{Pipe,Port}`
- [ADR 0008](0008-same-user-trust-boundary.md), [ADR 0009](0009-daemon-hardening-scope.md)
- [FURTHER_ANALYSIS.md](../security/FURTHER_ANALYSIS.md) H-2
