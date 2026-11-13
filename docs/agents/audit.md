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

`verify` checks chain integrity across rotations. `export` prints a JSON envelope with the entry
count and the `path` of the export, `<audit_path>/audit-export-<unix time>.jsonl` (`.csv` for
`--format csv`); the entries are in that file, one JSON object per line. Exports hold no secrets, but
RP IDs, denials and timing are still sensitive account metadata.

The export marks the words an agent wrote. A record with an `agent_note` (below) has
`"agent_supplied": ["agent_note"]` next to its `event` in the JSON export, and the CSV export's last
column, `agent_supplied`, names the field (it is empty for every other row). The records themselves,
and so the hash chain, are unchanged. Treat that text as untrusted: the daemon sanitizes it but does
not vouch for it.

Every record carries its schema version as `v`. This is version 5; readers accept every version
and a field added later is read as absent from an older record. Version 4 added `credential_scope`
and the wildcard registration reasons, version 5 the pre-request fields below.

## Operation records

`policy.allow` (the reservation), `policy.deny`, `policy.replay_served` and `operation.terminal` carry
the same keys; keys that do not apply yet are `null`:

| Group | Fields |
|---|---|
| Identity | `session_id_hash`, `request_id`, `escalation_id`, `profile_id`, `mode`, `principal_relationship` |
| Policy state | `revocation_epoch`, `grant_epoch`, `rule` (`exact` or `*`), `grant_source` (`config` or `granted`), `decision`, `evidence_source` (`agent` or absent) |
| Request | `action`, `rp_id`, `origin`, `top_origin` (null on the proxy path), `cross_origin` |
| Credential | `credential_ref`, `credential_scope` (`pinned`, `discovered`, `registration_pinned`; null before the candidates are chosen), `selection_rule`, `backend` (`local`, `pass`, `tpm`), `key_provider`, `counter_before`, `counter_after` |
| Approval | `approval_source` (schema 5): `ceremony` or `pre_request` for an operation that ran on an escalation approval or a pre-approval token, null when it ran on a rule or a grant |
| Outcome | `result` (`success`, `replay_served`, `denied`, `aborted`, `revoked`, `timeout`, `busy`, `error`), `failure_class` |

`credential_scope` says where the candidate credentials came from (schema version 4): `pinned` (the
profile's `credential_refs` at an exact rule), `discovered` (every credential of the site), or
`registration_pinned` (only the credentials the agent registered at that site, which is how a site
reached through `*` behaves once the agent has registered there). See
[Rules](rules.md#credential-selection).

A reservation and its terminal record share `request_id`. Evidence is always `agent`: agent-derived
UP and UV are never recorded, or described, as human interaction.

`policy.deny` and `policy.replay_served` also carry `reason` and `suppressed`. The reasons of a
registration at an unlisted site (`register = "request"` on the `*` rule) that was refused without a
prompt are `wildcard_registration_cap` (the profile holds `max_wildcard_registrations` such grants),
`wildcard_registration_rate` (`wildcard_registration_prompts_per_day` prompts already shown in the last
24 hours) and `wildcard_registration_cooldown` (a recent deny, timeout or repeated withdrawal started the
profile-wide cooldown). The reasons of a refused pre-request (see [Asking in advance](rules.md#asking-in-advance))
are `not_requestable` (the live rules do not resolve the action at the site to `request`, or this session
does not own the browser), `pre_request_rate_limited` (the session has a request pending or asked too
often) and `pre_request_not_enabled` (the profile does not list the action in `pre_request_actions`). A page can loop a
refused request, so refusals are coalesced per session, RP, action and reason: the first 16 in a
60 second window are written in full, and the rest are counted. The count is written as one
`policy.deny` with `suppressed` set to the number of refusals it stands for (its `origin` fields are
null; an RP the session no longer tracks is named `unknown`). The count is written when the next
window starts, when it reaches 1024, and when the session is revoked or dropped. Every refusal is
either a record or part of a count. `suppressed` is null on every other record.

## Other records

- Escalation: `escalation.requested`, `approved`, `denied`, `expired` (`reason` = `timeout`, `aborted`
  or `server_lost`) and `revoked` (operator revocation or policy reload), each with `origin` and
  `rule`. A registration at an unlisted site has `action = "register"` and `rule = "*"`. Schema 5 adds
  `source` (`ceremony`: a page raised it; `pre_request`: the agent asked in advance),
  `principal_session_id_hash` (a hash of the principal session that asked, or that owns the page's
  browser; never the session ID) and `agent_note`. `origin` is null for a pre-request, which has no page.
  `agent_note` is the `--note` of `passless agent request-access` or the `note` of the MCP tool,
  sanitized (one line, no markup or control characters) and cut to 200 bytes. It is on the pre-request's
  `escalation.requested` record only (null on every other record); a pre-request that joins an
  escalation another request already raised gets its own `escalation.requested` record, with the
  same `escalation_id`, its own `principal_session_id_hash` and its note. The note is never shown in a prompt. It is
  agent-supplied text and is stored as it was sent, so a secret an agent puts there is in the log.
- Pre-approvals (schema 5): `pre_approval.issued` (with `ttl_secs`) when a `register` pre-request is
  approved before a ceremony claims it, `pre_approval.consumed` (with the `request_id` of the
  registration that used it) and `pre_approval.expired` with a `reason`: `ttl`, `session_end` (the
  principal session ended; a token capped by the session's own end is usually recorded this way),
  `lease_revoked`, `policy_reload` or `grant_revoked`. Each carries `escalation_id`, `profile_id`,
  `rp_id`, `rule` and `principal_session_id_hash`; a token is issued once and ends exactly once. It
  is usable only after `issued` is written: if that record cannot be written, no token exists and the
  agent is told `unavailable`. A registration that only replays an earlier one (same challenge) does not
  spend a token.
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

Sign-ins to RPs outside the task; a `same-user` profile registering a credential (`rule = "*"` means a
site you had not listed, and `agent-admin grants list` shows each one with its `RULE`); repeated denials,
replays or budget exhaustion (a loop or a hostile page); escalations and their outcomes; whether the
site still holds a session after local teardown.
