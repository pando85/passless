# Agent policy automation gap plan

- **Status:** Active
- **Date:** 2026-07-19
- **Owners:** Passless maintainers
- **Covers:** [ADR 0001](../decisions/0001-agent-authentication-security-model.md) and [ADR 0002](../decisions/0002-native-webauthn-agent-architecture.md)
- **Baseline:** `make test-agent-validation` passed locally with swtpm on 2026-07-19

## Purpose

Close the gap between the supervised-only implementation and the accepted configurable policy:
exact-RP `deny`, `confirm`, or `allow` decisions for registration and authentication, explicit
human/policy UP and UV sources, and explicit delegated registration storage.

## Requirements

| ID | Requirement |
|---|---|
| RULE-01 | Every exact RP has independent registration and authentication policies. |
| RULE-02 | Missing rules and `deny` fail before prompt or credential access. |
| RULE-03 | `confirm` requires a fresh trusted prompt bound to one CTAP operation. |
| RULE-04 | `allow` skips notification but retains one-shot binding and consumption. |
| EVID-01 | UP source is explicitly `human` or `policy`. |
| EVID-02 | UV source is explicitly `human`, `policy`, or `none`. |
| EVID-03 | Invalid authorization/evidence combinations fail configuration. |
| EVID-04 | Audit and validation evidence identify the configured source without secrets. |
| STORE-04 | Delegated registration is denied unless an explicit target is configured. |
| STORE-05 | Delegated writes are exact-RP scoped and cannot enumerate, delete, or manage credentials. |
| COMPAT-01 | Human behavior remains unchanged when agents are disabled. |
| COMPAT-02 | Policy schema and digest changes invalidate ephemeral authority fail-closed. |

## Phase 1: Schema and policy digest

1. Add closed enums for authorization and evidence sources.
2. Add exact-RP rules containing registration and authentication ceremony policies.
3. Replace profile-wide `rp_ids`, `registration_allowed`, and `require_uv` policy authority.
4. Validate duplicate RPs, invalid combinations, start URLs, and delegated registration targets.
5. Bump the deterministic policy schema and include every rule and target in its digest.
6. Update principal capability output to summarize rules without implying broader authority.

Exit gate: malformed, ambiguous, missing, or unknown policy fails before runtime startup; digest tests
prove every security-relevant field changes the digest.

## Phase 2: Ceremony decisions and evidence

1. Resolve the exact action rule after parsing and matching the CTAP RP ID.
2. Return `deny` before displaying a prompt or activating credential scope.
3. Preserve the existing trusted prompt flow for `confirm`.
4. Resolve the same one-shot pending record automatically for `allow`.
5. Mint one-shot interaction evidence from the configured UP/UV sources.
6. Re-evaluate policy immediately before scope activation and key use.
7. Record decision and evidence sources in durable audit metadata.

Exit gate: table-driven tests cover every valid decision/evidence combination, wrong RP/action,
policy reload, replay, timeout, and audit failure.

## Phase 3: Delegated registration

1. Add an explicit delegated registration target, initially `human`.
2. Extend the filtered shared-storage view with an exact-RP registration scope.
3. Serialize writes through the existing daemon-owned human adapter and operation lock.
4. Keep iteration, deletion, credential management, fallback lookup, and unrelated writes denied.
5. Ensure newly registered credentials are not automatically added to authentication
   `credential_refs`; that remains an explicit policy update.

Exit gate: registration succeeds only for the configured RP/target and all unrelated storage
operations remain denied under concurrent human access and injected failures.

## Phase 4: Interfaces and documentation

1. Update config generation, examples, doctor output, capabilities, and administrative policy output.
2. Clearly distinguish human and policy UP/UV in documentation and audit output.
3. Remove supervised-only and autonomous-absence claims from ADR 0002, the implementation plan,
   validation plan, and agent guides.
4. Document migration from the experimental old profile fields to explicit rules.

Exit gate: generated examples parse, documentation links pass, and no interface claims that policy
evidence is human evidence.

## Phase 5: Validation

Deterministic validation must cover:

- Exact RP/action `deny`, `confirm`, and `allow` decisions.
- No notification call for `deny` or `allow`.
- Real/private-D-Bus prompt behavior for `confirm`.
- Transport and controlled-RP UP/UV flags for human, policy, and absent UV sources.
- Isolated and delegated registration/authentication matrices.
- Policy reload and one-shot replay prevention.
- Local, pass, and swtpm composition.
- Human E2E with agents compiled and disabled.
- Secret scanning and bounded fault scenarios.

Release-lab validation must additionally cover stock Chromium, real notification actions, hidraw
isolation, principal boundaries, delegated shared-store serialization, install/rollback/uninstall,
and cleanup inventory.

Exit gate: `make test-agent-validation`, full Rustfmt/Clippy/tests, and one complete recorded
`tools/agent-validation/run.sh --release` run pass with no required skip.

## Phase 6: Review and release

An independent review must assess policy-authorized flag semantics, policy administration,
automatic registration, delegated shared-store writes, one-shot races, device routing, audit
durability, and human-path regression. Critical and high findings block release.

## Current status

- ADR decision: complete.
- Deterministic supervised baseline including swtpm: passed locally.
- Schema and policy digest: implemented with a supervised legacy migration form.
- `deny`, `confirm`, and `allow` ceremony dispatch: implemented; browser E2E pending.
- Human and policy UP/UV interaction tokens and audit source fields: implemented; live flag correlation pending.
- Delegated registration scope and endpoint path: implemented; complete browser and concurrency validation pending.
- Updated autonomous validation scenarios: pending.
- Recorded Tier 2/Tier 3 release-lab evidence: pending.
- Independent security review: pending.
