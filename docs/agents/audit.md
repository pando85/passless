# Agent audit

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

Agent events are hash-chained, owner-only, append-oriented JSONL records. The authoritative field
list is [ADR 0014 section 12](../decisions/0014-agent-delegation.md#12-audit); this page summarises it.

## Where and how

The directory is `agents.audit_path`. It must be protected from the agent (in a different-user
deployment it is) and must not overlap storage roots. `passless agent-admin profile check` and the
daemon's start-up diagnostics verify ownership and mode.

Audit gates credential use. Before any credential is created or used, the daemon appends and fsyncs a
reservation record; if that fails, the operation does not proceed. Every reservation is closed by
exactly one terminal record. A terminal write failure puts agent support into a degraded, fail-closed
state until an administrator repairs it; your own authenticator stays available. After a crash, the
next start closes open reservations from the newest two segments (`failure_class = abandoned`).

```bash
passless agent-admin audit status
passless agent-admin audit verify
passless agent-admin audit export --format json   # or csv
```

`verify` checks chain integrity across rotations. Exports hold no secrets, but RP IDs, denials and
timing are still sensitive account metadata.

## Operation records

`policy.allow` (the reservation), `policy.deny`, `policy.replay_served` and `operation.terminal` carry
the same keys; keys that do not apply yet are `null`:

| Group | Fields |
|---|---|
| Identity | `session_id_hash`, `request_id`, `escalation_id`, `profile_id`, `mode`, `principal_relationship` |
| Policy state | `revocation_epoch`, `grant_epoch`, `rule` (`exact` or `*`), `grant_source` (`config` or `granted`), `decision`, `evidence_source` (`agent` or absent) |
| Request | `action`, `rp_id`, `origin`, `top_origin` (null on the proxy path), `cross_origin` |
| Credential | `credential_ref`, `selection_rule`, `backend` (`local`, `pass`, `tpm`), `key_provider`, `counter_before`, `counter_after` |
| Outcome | `result` (`success`, `replay_served`, `denied`, `aborted`, `revoked`, `timeout`, `busy`, `error`), `failure_class` |

A reservation and its terminal record share `request_id`. Evidence is always `agent`: agent-derived
UP and UV are never recorded, or described, as human interaction.

## Other records

- Escalation: `escalation.requested`, `approved`, `denied`, `expired` (`reason` = `timeout`, `aborted`
  or `server_lost`) and `revoked` (operator revocation or policy reload), each with `origin` and
  `rule`.
- Granted rules: `granted_rule.add` and `granted_rule.revoke`.
- Browser sessions: `grant.request` and `grant.approve` (profile, principal, RP scope, TTL), and
  browser lease creation, expiry, revocation, exit and cleanup.
- Daemon: start, stop, degraded state and recovery, including the human backend kind.

Request caps answered `busy` before a ceremony exists write no operation record.

## What is never recorded

Private keys, PINs, bearers, cookies, tokens, raw assertions or signatures, client-data hashes,
credential records and browser profile contents. CDP response bodies are never recorded either: they
may hold cookies and session state.

## Limits

The local hash chain is not an external trust anchor: owner-only permissions and chaining detect
accidental damage and non-root edits, but host root can rewrite local history, and a deleted rotated
file cannot be reconstructed. A WebAuthn audit shows authentication, not what the agent did inside the
site afterwards.

## What to look for

Sign-ins to RPs outside the task; a `same-user` profile registering a credential; repeated denials,
replays or budget exhaustion (a loop or a hostile page); escalations and their outcomes; whether the
site still holds a session after local teardown.
