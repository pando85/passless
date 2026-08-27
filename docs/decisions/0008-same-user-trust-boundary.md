# ADR 0008: Same-user agent trust boundary and browser hardening scope

- **Status:** Accepted
- **Date:** 2026-08-27
- **Decision owners:** Passless maintainers
- **Related decisions:** [ADR 0007](0007-unified-agent-identity-modes.md), [ADR 0005](0005-delegated-autonomous-authentication-redesign.md)
- **Supersedes:** the framing of C-1 as an open security gap in [FURTHER_ANALYSIS.md](../security/FURTHER_ANALYSIS.md)

## Context

The `same-user` agent mode is intended to be a low-security but practical way to give an
agent (e.g. an LLM-driven automation process) access to the user's existing passkeys. Per
ADR 0007, a same-user profile is explicitly trusted as the authenticator user; its RP
rules, short session TTLs, credential selectors, operation binding, and audit limit
authority — they do not attempt to isolate the agent from the user.

In this mode the daemon is unprivileged (`daemon_uid != 0`) and the browser is spawned
with the same UID/GID as the daemon (`is_trusted_same_user_port_launch`). Security
analysis item C-1 flagged that the port-mode spawn path applies no process hardening and
framed this as a high-severity gap, listing `close_range`, `setuid`, rlimits, and
`PR_SET_NO_NEW_PRIVS` as skipped.

Review of the actual code shows this framing is inaccurate:

- `HardenedChildSetup::apply()` is already same-user-aware. `close_range`,
  `setgroups`/`setgid`/`setuid`, and all rlimits are gated behind `!same_user` there.
  They would not be applied in same-user mode even if `apply()` were called.
- The only controls the trusted port path skips are `PR_SET_PDEATHSIG` and
  `PR_SET_NO_NEW_PRIVS`.

More fundamentally, under Linux there is no kernel-enforced boundary between
same-UID processes, independent of what `pre_exec` does: a same-UID browser can
`ptrace` the daemon, read `/proc/<daemon>/mem` and `/proc/<daemon>/fd/*`, connect to the
user-owned sign socket, and read the bearer token from the user's environment or memory.
The headline C-1 scenario ("browser exploit → daemon compromise") is already true of any
same-UID process and cannot be prevented by spawn-time hardening.

## Decision

1. **Same-user mode does not attempt OS-level process isolation between the browser and
   the daemon.** The security boundary for same-user agent operation lives in the policy
   layer: exact RP rules, grant scoping, short session TTLs, credential selectors,
   operation binding, and complete audit. Same-UID local compromise is inside the trust
   boundary, as ADR 0007 already states.

2. **Omitting `PR_SET_NO_NEW_PRIVS` in same-user port mode is intentional.**
   Chromium requires either its setuid `chrome-sandbox` helper or an unprivileged user
   namespace during startup; NNP would break the helper path and provides negligible
   protection against an attacker who already runs as the same UID.

3. **Residual work is resilience/hygiene only, not security:**
   - Close unintended inherited daemon FDs in the same-user port-mode spawn (robustness:
     stale `/dev/uhid`, listen sockets, and pipe ends can interfere with lease cleanup).
   - Set `PR_SET_PDEATHSIG` (or verify equivalent orphan reaping) so a browser is not
     orphaned when the daemon dies.
   - Optionally apply rlimits for resource robustness (limit session starvation), framed
     as reliability, not sandboxing.

## Consequences

- C-1 is closed as "accepted — by design" and no longer tracked as an open security gap.
- `FURTHER_ANALYSIS.md` keeps a pointer here; its severity framing of C-1 is superseded.
- Effort previously allocated to same-user spawn hardening is redirected to the
  cross-attack-surface items where a real boundary exists (C-2 daemon privileges,
  H-1 D-Bus notification integrity, C-3 grant approval model).
- Trade-off accepted: any process running as the user can drive the sign socket subject
  to policy. This is the deliberate price of the mode's practicality and matches
  ssh-agent / gpg-agent session trust models.

## References

- `cmd/passless/src/agent/browser.rs` `is_trusted_same_user_port_launch`, `spawn_browser_port_mode`
- `cmd/passless/src/agent/launcher.rs` `HardenedChildSetup::apply`
- [ADR 0007](0007-unified-agent-identity-modes.md) threat table: same-user trust boundary
- [FURTHER_ANALYSIS.md](../security/FURTHER_ANALYSIS.md) C-1 (superseded framing)
