# Agent audit

> **EXPERIMENTAL** — Agent mode is not yet validated for production use.

Agent audit events are hash-chained, owner-only, append-oriented JSONL records. They cover
authorization lifecycle, credential use, browser leases, policy changes, denials, and degradation.

## Audit path

The audit directory is configured in `[agents].audit_path` and must be owned by root with mode
`0700`. It is outside every principal boundary and inaccessible to agent processes.

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless-agent/audit"
```

## Event categories

Audit events include:

- **Daemon lifecycle:** agent subsystem start, stop, degraded state, and recovery.
- **Principal and endpoint:** creation, readiness, activation, draining, destruction, and failure.
- **Policy:** load, reload, denial, expiry, revocation, and generation changes.
- **Authorization:** intent and grant creation, binding, approval, cancellation, consumption, and timeout.
- **Prompt:** display, approval, denial, timeout, and UV result.
- **Credential:** isolated credential reservation, creation, use, revocation, quarantine, and deletion; delegated credential reservation, use, and state-update result.
- **Browser lease:** start, expiry, revocation, browser exit, cleanup, quarantine, and recovery.
- **Audit integrity:** rotation, verification, checkpoint, degradation, and acknowledgement.

## Event format

Each event is a single-line JSON record containing:

- `seq`: monotonically increasing sequence number.
- `prev_hash`: SHA-256 hash of the previous record (or `null` for the first record after rotation).
- `hash`: SHA-256 hash of this record's canonical fields.
- `timestamp`: wall-clock RFC 3339 timestamp for display.
- `monotonic_ns`: monotonic duration in nanoseconds for expiry decisions.
- `event`: event type identifier.
- Event-specific fields (principal, profile, endpoint, mode, policy generation, authorization ID, RP ID, action, credential reference, result, etc.).

## Durability and secrecy

- Events are appended and fsynced before credential creation or use.
- A terminal write failure after an irreversible response places agent support in persistent degraded mode until an administrator repairs and acknowledges it.
- Human UHID operations remain available during agent audit degradation.
- Audit events never include private keys, PINs, capabilities, cookies, tokens, raw assertions, client-data hashes, raw credential records, or browser profile contents.
- CDP method and outcome metadata may be recorded, but CDP response bodies are not audit-recorded.

## Hash-chain verification

The `agent-admin audit verify` command checks hash-chain integrity across rotations:

```bash
passless agent-admin audit verify
```

Verification reads all event files in sequence order, recomputes hashes, and reports any discontinuity. A break in the chain indicates potential tampering, corruption, or an incomplete write.

## Rotation

Audit files are rotated based on size or time. The current rotation policy is:

- Rotate when the active file exceeds a configured size threshold.
- Retain rotated files with a `.1`, `.2`, etc. suffix.
- The first record after rotation has `prev_hash = null` and starts a new chain.

Optional external checkpoints (e.g., TPM-anchored or remote) can anchor the chain to an independent trust root. This is not implemented in the first release.

## Export

The `agent-admin audit export` command writes non-secret events to a temporary path:

```bash
passless agent-admin audit export --format json
passless agent-admin audit export --format csv
```

Export excludes secrets and sensitive fields. The command reports the temporary file location.

## Degraded mode

If an irreversible result (e.g., successful assertion) cannot be recorded due to audit write failure:

1. Agent support enters persistent degraded mode.
2. All subsequent agent operations are denied.
3. Human operations remain available.
4. The administrator must repair the audit path and acknowledge the degradation:

```bash
passless agent-admin audit status
# After repair:
passless agent-admin audit verify
```

## Integrity limits

Audit integrity is limited to:

- **Local protection:** Owner-only permissions and hash-chaining detect tampering by non-root users.
- **No external anchoring:** Host root can rewrite local audit without external anchoring. Optional TPM or remote checkpoints are not implemented in the first release.
- **Rotation gaps:** If rotation fails or files are lost, the chain may have discontinuities. Verification reports these but cannot reconstruct missing records.
