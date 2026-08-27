# ADR 0012: Grant audit emission and D-Bus notification approval integrity

- **Status:** Accepted (deferred implementation)
- **Date:** 2026-08-27
- **Decision owners:** Passless maintainers
- **Related decisions:** [ADR 0001](0001-agent-authentication-security-model.md), [ADR 0007](0007-unified-agent-identity-modes.md), [ADR 0008](0008-same-user-trust-boundary.md)
- **Affects:** security analysis items C-3 and H-1 in [FURTHER_ANALYSIS.md](../security/FURTHER_ANALYSIS.md)

## Context

### C-3 — Self-approval of grants

FURTHER_ANALYSIS frames the agent requesting and approving its own grants as a
high-severity gap. Ground-truth review (2026-08):

- `AdminAuthority` is an empty seal. `admin_authority()` increments
  `ADMIN_AUTHORITY_TOKEN`, which is **never read anywhere**. `approve_grant` and
  `revoke_grant` take it as an unused `_authority` parameter. It provides no checking.
- However, autonomy without human approval is the **designed behavior**: ADR 0001
  accepts unattended operation, and ADR 0007 declares `authorization="allow"` profiles
  trusted to authorize within their RP rules. The self-approval flow is not a bypass of
  an intended check; it is the `allow` policy itself.
- Real defenses around grants already exist: 32-byte session capability with
  constant-time verification, TTL clamping, RP re-validation, max concurrent grants,
  peer UID checks.
- **The genuine defect the review missed:** grant requests and approvals emit **zero
  audit records in production**. `GrantRequestBuilder` and `GrantApproveBuilder` exist
  in `audit_events.rs` but are used only in tests. Only revocations are audited. The
  complete-audit guarantee that ADRs 0001/0007 rely on for autonomous same-user
  operation is therefore partially absent.

### H-1 — D-Bus notification action injection

Ground-truth review (2026-08):

- notify-rust 4.18's `wait_for_action` exposes only the action string to the callback.
  The D-Bus sender of `ActionInvoked` is not available through that API.
- Existing mitigations: `min_review_delay_ms` (default 1000ms), notification-server
  capability gate (fail-closed on unknown servers), action-string validation. None of
  these authenticate the signal — a same-session process can synthesize
  `ActionInvoked("approve")`.

Unlike C-1/H-2/H-3, H-1 is **in scope for same-user mode**: the same-user trust model
still distinguishes the *agent* from the *human*. `authorization="confirm"` exists
precisely so a human approves. Synthetic signal injection collapses that human/agent
distinction even within an uncompromised UID — the agent (or any same-session process)
could self-confirm a ceremony intended for human approval. ADR 0008's "same-UID
compromise is inside the boundary" does not neutralize this, because the boundary here
is human-vs-agent, not UID-vs-UID.

## Decision

### C-3

1. **Self-approval of grants is accepted as designed** for profiles whose RP rules
   authorize it. The `AdminAuthority` token is cosmetic and its cosmetics are recorded
   here as known-and-accepted; a later cleanup may simplify or remove the dead counter.
2. **Backlogged action item (C-3a): emit production audit records for grant request and
   grant approval** using the existing `GrantRequestBuilder`/`GrantApproveBuilder`,
   recording at minimum: request ID, profile, principal identity, RP IDs, credential
   scope, TTL, and decision. This closes the observability gap without changing the
   approval model.

### H-1

1. **H-1 remains an open gap and is in scope for same-user mode.**
2. **Backlogged action item (H-1a): verify the D-Bus sender of `ActionInvoked`.** The
   fix requires bypassing notify-rust's `wait_for_action` and subscribing to
   `org.freedesktop.Notifications.ActionInvoked` via zbus directly, then validating the
   signal's sender matches the notification server's well-known-name owner (resolved at
   prompt time). Reject actions from any other sender. Medium effort.
3. `min_review_delay_ms` is kept as a timing heuristic only, documented as
   non-authenticating.

## Consequences

- C-3: approval model unchanged; one backlog item (C-3a audit emission).
- H-1: one backlog item (H-1a sender validation), scoped and specified for the next
  same-user hardening round.
- Both items are deferred for later implementation, to be picked up alongside the
  same-user improvements batch.

## References

- `cmd/passless/src/agent/intent.rs` `AdminAuthority`, `admin_authority`, dead counter
- `cmd/passless/src/agent/grant.rs` `approve_grant` / `revoke_grant` (unused `_authority`)
- `cmd/passless/src/agent/runtime/browser_ensure.rs` self-approval flow
- `cmd/passless/src/agent/audit_events.rs` `GrantRequestBuilder`/`GrantApproveBuilder`
  (test-only usage)
- `cmd/passless/src/agent/prompt.rs` `wait_for_action`, server capability gate,
  `min_review_delay_ms`
- [FURTHER_ANALYSIS.md](../security/FURTHER_ANALYSIS.md) C-3, H-1
