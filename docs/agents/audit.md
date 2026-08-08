# Agent audit

> **EXPERIMENTAL** — Agent mode is not yet validated for production use.

Agent audit events are hash-chained, owner-only, append-oriented JSONL records covering authorization lifecycle, credential use/creation, browser leases, policy changes, denials, and degraded-state handling.

## Audit path

The audit directory is configured in `[agents].audit_path` and must be protected from principal processes. A typical daemon-owned layout is:

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless-agent/audit"
```

Use `profile check` / startup diagnostics to verify ownership, mode, and path isolation on the deployment host.

## Event categories

Audit events include:

- **Daemon lifecycle:** agent subsystem start, stop, degraded state, and recovery.
- **Principal and endpoint:** creation, readiness, activation, draining, destruction, and failure.
- **Policy:** load/reload, allow/deny decisions, expiry, revocation, and generation changes.
- **Authorization/session:** intents, grants/session authority, binding, cancellation, consumption, replay rejection, timeout, and operation-budget exhaustion where represented by the current event schema.
- **Prompt/human interaction:** display, approval, denial, timeout, and verification outcome.
- **Credential:** isolated or human-namespace credential selection, creation, use, state update, revocation, quarantine, and deletion as applicable to the active mode.
- **Browser lease:** start, expiry, revocation, browser exit, cleanup, quarantine, and recovery.
- **Audit integrity:** rotation, verification, degradation, and acknowledgement.

The removed `delegated-session` identity mode is not a current audit category. Current identity modes are `same-user` and `isolated`. Administrative types may retain historical names such as `delegation` for grant lifecycle compatibility; interpret events by their actual profile mode/namespace rather than inferring a removed identity mode from an old API noun.

## Effective identity and evidence

Audit is the place where Passless can distinguish security facts that a relying party generally cannot.

For every credential operation, records should make it possible to determine at least:

- profile and identity mode (`same-user` or `isolated`);
- human vs isolated credential namespace where the event schema supports it;
- concrete RP ID and action;
- policy generation / authorization result;
- credential reference where safe and applicable;
- authorization source;
- UP source (`agent`, `human`, or absent);
- UV source (`agent`, `human`, or absent);
- terminal result;
- browser/session lifecycle context required for investigation.

**Agent-derived UP/UV must never be described as human evidence.** An autonomous same-user assertion may set ordinary WebAuthn UP/UV flags that the RP accepts as authentication, while audit must still record that the evidence source was the bound agent/session policy path rather than ceremony-time human PIN/biometric interaction.

## Event format

Each event is a single-line JSON record containing integrity/lifecycle fields such as:

- `seq`: monotonically increasing sequence number;
- `prev_hash`: hash of the previous record where the current rotation format links one;
- `hash`: hash of the current canonical event record;
- wall-clock timestamp for operator display;
- monotonic timing information where used for expiry decisions;
- `event`: event type identifier;
- event-specific profile, RP, action, policy, credential, result, and lifecycle metadata.

Do not treat wall-clock timestamps as the source of authority expiry when the runtime uses monotonic state for security decisions.

## Durability and fail-closed behavior

Credential use/creation is gated by the audit subsystem rather than being logged on a best-effort basis after the fact.

Operational expectations:

- required audit reservation/recording occurs before irreversible credential use/creation;
- an audit write/reservation failure prevents the agent credential operation from proceeding successfully;
- terminal failure after an irreversible step moves agent support into the documented degraded/fail-closed path;
- ordinary human authenticator availability should not be coupled to agent-audit degradation unless explicitly required by the human path itself.

Check current state with:

```bash
passless agent-admin audit status
passless agent-admin audit verify
```

Repair audit storage before resuming agent credential use after a degraded/integrity failure.

## Secrecy requirements

Audit must not contain:

- credential private keys or raw wrapped key material;
- PINs or local-verification secrets;
- principal/session bearer capabilities;
- browser cookies or storage values;
- raw assertion signatures;
- unrestricted credential records;
- full CDP response bodies;
- browser profile contents.

Non-secret references, bounded policy metadata, RP IDs, evidence source labels, lifecycle state, and result codes may be recorded when required for security investigation.

## Browser/CDP events

CDP is full browser-session authority, but audit should avoid turning that authority into a second secret store.

Record bounded method/outcome/lifecycle metadata where useful; do not record raw CDP response bodies because they may contain cookies, DOM, tokens, network data, or other authenticated session state.

Passless audit also cannot prove what application-level actions an agent performed after login unless those actions are independently visible through browser/application telemetry. A successful WebAuthn audit record proves authentication activity, not a complete post-login action trace.

## Hash-chain verification

Verify the local chain with:

```bash
passless agent-admin audit verify
```

A discontinuity can indicate tampering, corruption, rotation/storage failure, or incomplete write. Preserve affected files and investigate before treating later local history as trustworthy.

## Rotation

Rotation retains bounded audit storage while starting/continuing integrity state according to the implementation's current format. Operators should verify across the retained files rather than assuming that file existence alone proves an unbroken history.

If rotated files are deleted or rotation fails, verification may detect a discontinuity but cannot reconstruct missing records.

## Export

Export non-secret event views with:

```bash
passless agent-admin audit export --format json
passless agent-admin audit export --format csv
```

Treat exports as security-sensitive operational records even though they exclude credential secrets: RP IDs, identities, denials, and session timing can still reveal account/activity metadata.

## Routine review

For privileged `same-user`, autonomous, wildcard, registration-enabled, or CDP-exposed profiles, review audit more aggressively.

Useful questions include:

- Did authentication occur to an RP outside the operator's intended task?
- Did a same-user profile register a new human credential unexpectedly?
- Was UP/UV agent-derived or human-derived?
- Are repeated denials/replays/operation-budget exhaustion signs of a bad automation loop or hostile page behavior?
- Did policy generation change during a task?
- Did a browser/session survive longer than expected locally?
- Does the RP still retain a server-side session after local teardown?

## Integrity limits

The local hash chain is not an external trust anchor.

- Owner-only permissions and chaining protect/detect many non-root modifications and accidental corruption.
- Host root can rewrite local files/state unless the chain is anchored independently.
- A lost rotated file cannot be reconstructed by verification.
- Audit of WebAuthn does not scope or enumerate all actions performed inside the authenticated RP session.

A future TPM/remote checkpoint could strengthen tamper evidence, but until such anchoring is implemented, do not claim root-resistant audit immutability.
