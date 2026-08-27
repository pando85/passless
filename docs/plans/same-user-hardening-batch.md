# Same-User Hardening Batch — Implementation Plan

- **Status:** Approved for execution
- **Date:** 2026-08-27
- **Scope:** The three same-user-relevant backlog items from the FURTHER_ANALYSIS review
  round: C-3a (grant audit), C-1 residuals (spawn hygiene), H-1a (D-Bus sender
  validation). Isolated-cross-user items (C-2, H-2, H-3) are out of scope.
- **Decision basis:** [ADR 0008](../decisions/0008-same-user-trust-boundary.md),
  [ADR 0012](../decisions/0012-grant-audit-and-notification-approval-integrity.md)
- **Execution model:** the orchestrator does not write code. Each item is implemented by
  a `general` subagent, verified, and committed as **one commit per item**, in the
  order listed below. Docs commit first.

---

## Phase 0 — Commit the decision documents

Uncommitted from the review round: ADRs 0008–0012 and the six status notes in
`docs/security/FURTHER_ANALYSIS.md`.

- **Files:** `docs/decisions/0008-*.md` … `0012-*.md`, `docs/security/FURTHER_ANALYSIS.md`
- **Verify:** `git status` shows only these doc files; nothing else staged.
- **Commit message:**
  ```
  docs: record decisions for security analysis gaps C-1..H-3

  Add ADR 0008-0012 and status notes in FURTHER_ANALYSIS.md for the
  six remaining findings: same-user trust boundary, daemon hardening
  scope, namespace isolation scope, seccomp scope, grant audit and
  D-Bus notification approval integrity.
  ```

---

## Item 1 (C-3a) — Emit production audit records for grant request/approval

**Goal:** every grant request and grant approval produces an audit record. Today
`GrantRequestBuilder` and `GrantApproveBuilder` exist in
`cmd/passless/src/agent/audit_events.rs:1445-1484` but are used only in tests; only
revocations are audited (via `AdminGrantRevokeBuilder` at `runtime.rs:4475`).

**Files:**
- `cmd/passless/src/agent/grant.rs` — hook `approve_grant` (line ~564) and the request
  creation path (`request_grant` / dynamic variant) to build + emit audit events.
- `cmd/passless/src/agent/audit_events.rs` — builders already exist; only add fields if
  genuinely missing (principal identity, decision).
- `cmd/passless/src/agent/runtime/browser_ensure.rs` and `runtime.rs` (~5125-5133) —
  grant issuance call sites that flow through the `GrantManager`; ideally the events are
  emitted inside `grant.rs` so all call sites benefit without call-site changes.
- Tests: extend the existing tests in `audit_events.rs` / `grant.rs` to assert events
  are actually emitted into the audit sink in production code paths (not just test
  helper usage).

**Acceptance criteria:**
1. Approving a grant emits a `GrantApprove` audit record with: request ID, RP IDs,
   principal/profile identity, TTL applied, decision.
2. Submitting a grant request emits a `GrantRequest` audit record.
3. No change to the approval model itself (self-approval remains as designed).
4. Existing audit tests still pass; new test(s) cover the production emission path.

**Verification:**
```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test grant
cargo test audit
```

**Commit message:**
```
feat: audit grant request and approval events in production

Wire GrantRequestBuilder and GrantApproveBuilder into the GrantManager
so grant lifecycle events are recorded outside of tests. Closes the
observability gap identified in the C-3 review (ADR 0012). Approval
behavior is unchanged; this is purely observability.
```

**Subagent prompt outline:** implement item 1 as specified above; discover the audit
sink plumbing by following how `AdminGrantRevokeBuilder` is emitted at
`runtime.rs:4475`; keep the change minimal; run the verification commands; report diff
summary and test results. Do NOT commit — the orchestrator commits after review.

---

## Item 2 (C-1 residuals) — Same-user spawn hygiene: FD closure, PDEATHSIG, rlimits

**Goal:** close the resilience-only leftovers from ADR 0008 for the trusted same-user
port-mode spawn:

1. **Close inherited FDs** in the same-user port spawn path (uses
   `pre_exec` that skips `HardenedChildSetup::apply()` entirely — see
   `browser.rs:2241-2254`). Only `setsid()` runs today, so the child inherits all
   daemon FDs (sockets, audit files, UHID). Apply FD closure preserving only the FDs
   the spawn legitimately needs. Reuse `close_range_preserving()` from
   `launcher.rs:692` — do not write a second implementation.
2. **`PR_SET_PDEATHSIG`** on the same-user spawn so the browser is reaped if the
   daemon dies unexpectedly (currently it can be orphaned silently — inconsistent with
   the hardened path at `launcher.rs:699`).
3. **Optional rlimits** (`RLIMIT_NOFILE`, `RLIMIT_NPROC`, `RLIMIT_CORE`) on same-user
   spawns for damage containment. Keep generous values; Chromium and the profile dir
   must keep working. `RLIMIT_AS` excluded — too risky for Chromium.

**Explicitly NOT in scope:** `PR_SET_NO_NEW_PRIVS` on the same-user path (Chromium's
setuid sandbox helper may need it — see comment at `browser.rs:2244-2247`, recorded in
ADR 0008).

**Files:**
- `cmd/passless/src/agent/browser.rs` — same-user port spawn pre_exec (line ~2241).
- `cmd/passless/src/agent/launcher.rs` — reuse existing helpers; only touch if a small
  refactor is needed to make `close_range_preserving()` callable from the same-user
  pre_exec without invoking the rest of `apply()`.

**Acceptance criteria:**
1. Browser spawned in same-user port mode inherits no daemon FDs beyond the intended
   ones.
2. Browser receives SIGTERM if the daemon exits.
3. `PR_SET_NO_NEW_PRIVS` remains unset on the same-user path.
4. Chromium's setuid sandbox is not broken (guard via the existing warning comment;
   verified at runtime by the user, not by unit tests).
5. e2e login to idm.grigri.cloud still works (ask the user to re-verify, or run the
   existing trace script `/tmp/opencode/fresh_idm_trace.py`).

**Verification:**
```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test browser
# runtime smoke: restart passless, re-run the idm.grigri.cloud login trace
```

**Commit message:**
```
fix: close inherited FDs and set PDEATHSIG on same-user browser spawn

Same-user port-mode spawns skipped all pre_exec hardening including FD
closure and PDEATHSIG, letting the browser inherit daemon FDs and
survive daemon death as an orphan. Apply FD closure and PR_SET_PDEATHSIG
on the same-user path, keeping PR_SET_NO_NEW_PRIVS unset to preserve
Chromium's setuid sandbox helper (per ADR 0008). Resilience hygiene
only — same-UID processes are inside the trust boundary.
```

**Subagent prompt outline:** implement item 2 as specified; reuse
`close_range_preserving()`; keep the NNP exclusion; run the build/test verification
commands; note that runtime verification is done by the orchestrator/user; report diff
summary. Do NOT commit.

---

## Item 3 (H-1a) — Validate the D-Bus sender of `ActionInvoked`

**Goal:** a confirmation/UV prompt only honors an `approve` action that came from the
actual notification server. Today `prompt.rs:627` (`handle.wait_for_action(...)`)
receives only the action string from notify-rust 4.18 and cannot authenticate the
sender — any same-session process can forge `ActionInvoked("approve")` (see
`prompt.rs:1529-1538` test helper doing exactly this).

**Approach:** bypass `wait_for_action` for the action-waiting part:

1. At `show()`, resolve the notification server's well-known-name owner
   (`org.freedesktop.Notifications` → unique `:1.x` name) via zbus on the session bus.
2. Install a zbus match rule for
   `org.freedesktop.Notifications.ActionInvoked`, filtering the arrival loop by
   (a) the notification ID returned from `Notify` and (b) **sender == the owner
   resolved at step 1**.
3. Reject/ignore anything else (`ActionAmbiguous`/timeout path is fail-closed already).
4. Keep all existing mitigations (`min_review_delay_ms`, server-capability gate,
   action-string validation).

**Files:**
- `cmd/passless/src/agent/prompt.rs` — the main change (around lines 552-666 and the
  `wait_for_action` closure at ~627).
- `cmd/passless/src/agent/notification.rs` — same `wait_for_action` pattern at lines
  163, 265; apply the same sender check only if this path gates a security decision
  (evaluate — informational notifications don't need it; note decision in the commit).
- `Cargo.toml` — zbus is already a transitive dep via notify-rust 4.18; add it as a
  direct dependency matching the version notify-rust uses, to avoid a second zbus in
  the tree.
- Tests: the existing synthetic-injection helper at `prompt.rs:1529-1538` must now
  only be able to trigger actions from the test-owned bus name, and the positive test
  path must demonstrate that a message from a wrong sender is ignored.

**Acceptance criteria:**
1. A forged `ActionInvoked("approve")` from any bus name other than the notification
   server's owner is ignored.
2. A valid action from the notification server still works (approval flow for
   `authorization="confirm"` profiles remains functional).
3. `min_review_delay_ms`, capability gating, and action validation unchanged.
4. No second zbus version pulled in.

**Verification:**
```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test prompt
cargo tree -d zbus   # single version
# runtime: trigger a real confirm prompt and approve it from the UI
```

**Commit message:**
```
fix: validate D-Bus sender of notification ActionInvoked signals

Replace notify-rust wait_for_action with a raw zbus match that verifies
the ActionInvoked sender matches the notification server's unique bus
name resolved at notify time. Prevents any same-session process other
than the notification server from forging approval (H-1, ADR 0012).
Existing timing heuristic and capability gating are retained as-is.
```

**Subagent prompt outline:** implement item 3 as specified; inspect how `Handle` in
notify-rust 4.18 handles the zbus connection so we subscribe on the same connection or
appropriately; keep the API surface of `prompt()` unchanged; update the test helper so
the test-mode injection path can still drive the flow but production requires the
correct sender; run verification; report diff. Do NOT commit.

---

## Sequencing and hand-off rules

- Execute strictly in order. Do not start item N+1 until item N is committed green.
- Orchestrator reviews each subagent diff **before** committing.
- Subagents must not `git commit` / `git push`.
- Branch: `fix/security-toctou-url-validation-sign-server`.
- Conventional commits enforced (each message above satisfies commitlint).
- After all items: full suites — `cargo clippy --all-targets --all-features -- -D
  warnings`, `cargo test`, plus a full-login regression (e2e trace).

## Risks / watch-outs

- **Item 2:** PDEATHSIG makes browser lifetime bound to the daemon; if any flow
  intentionally lets the browser outlive the daemon, flag it before merging.
- **Item 3:** the notification server can restart between `show()` and action arrival;
  the unique-name owner check naturally fails then (fail-closed) — acceptable; log it.
- **Item 3:** notify-rust version upgrades might change the zbus version — pin-match
  to `notify-rust`'s zbus to avoid duplication (check `Cargo.lock`).

## Open items for the user before kicking off

1. Commit Phase 0 docs now, or fold into the batch end?
2. Item 2 runtime verification (browser compile/restart) — should the orchestrator
   pause after item 2's commit so you can re-run the login trace manually?
3. Item 3: include `notification.rs` only if it gates a security decision — subagent
   to evaluate and report before committing; OK?
