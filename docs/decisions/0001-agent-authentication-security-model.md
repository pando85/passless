# ADR 0001: Configurable agent authentication policy

- **Status:** Accepted
- **Date:** 2026-07-19
- **Decision owners:** Passless maintainers
- **Implementation status:** In progress
- **Related decision:** [ADR 0002](0002-native-webauthn-agent-architecture.md)
- **Implementation plan:** [Agent policy automation gap plan](../plans/agent-policy-automation-gap.md)
- **Supersedes:** the supervised-only agent policy accepted on 2026-07-13

## Context

Passless exposes ordinary FIDO2/WebAuthn ceremonies through UHID. A stock browser validates
the origin-to-RP relationship and sends CTAP requests to Passless. Agent profiles need both
supervised and unattended behavior: an operator may deny an operation, require a fresh trusted
confirmation, or authorize it in advance for an exact RP.

The previous decision required a prompt for every agent ceremony and prohibited policy from
providing UP or UV. That made production-path testing and intended unattended agent operation
depend on debug-only approval shortcuts. It also made registration behavior a profile-wide
boolean instead of an explicit RP and action decision.

Autonomous WebAuthn deliberately changes the meaning of authenticator evidence. A policy-based
UP or UV assertion records operator authorization for an isolated machine principal; it is not
a claim that a human interacted with that ceremony. RPs generally cannot distinguish those
sources. Operators must therefore opt in explicitly and accept the RP-visible semantics.

## Decision

Passless keeps two credential-ownership modes:

| Mode | Credential ownership | Browser-session result |
|---|---|---|
| `isolated` | Profile-specific credential and PIN storage | Separate agent credential |
| `delegated-session` | Explicitly selected human credentials and an explicit registration target | Same RP identity as the selected human account |

Autonomy is not a third mode. Each profile contains rules for exact RP IDs, and each rule defines
registration and authentication independently.

### Ceremony policy

Each registration or authentication policy contains:

```text
authorization: deny | confirm | allow
user_presence: human | policy
user_verification: human | policy | none
```

The meanings are:

- `deny`: reject before credential access and do not prompt.
- `confirm`: require a fresh trusted approval bound to the active endpoint and CTAP operation.
- `allow`: resolve the operation from current administrator policy without a notification.
- `user_presence = human`: set UP only after the bound trusted confirmation.
- `user_presence = policy`: set UP from the exact current policy rule and record that source.
- `user_verification = human`: set UV only after the production PIN/platform-verification path.
- `user_verification = policy`: set UV from the exact current policy rule and record that source.
- `user_verification = none`: do not require or assert UV unless the CTAP request independently
  requires verification, in which case the normal authenticator behavior applies.

Invalid combinations fail configuration. In particular, `authorization = allow` cannot use
`user_presence = human`, and `authorization = deny` cannot assert UP or UV.

Missing profiles, rules, actions, evidence settings, storage targets, or policy generations deny.
There is no permissive default.

### Exact RP policy

Rules use normalized exact RP IDs. They do not accept schemes, ports, paths, wildcards, trailing
dots, IP addresses, or public suffixes. The stock browser remains responsible for validating
whether an origin may use the requested RP ID. Passless sees and validates the CTAP RP ID, not the
exact browser origin.

An illustrative profile is:

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless-agent/audit/events.jsonl"

[agents.profiles.release-bot]
mode = "isolated"
principal_user = "passless-release"

[[agents.profiles.release-bot.rules]]
rp_id = "github.com"
register = { authorization = "allow", user_presence = "policy", user_verification = "policy" }
authenticate = { authorization = "allow", user_presence = "policy", user_verification = "policy" }

[agents.profiles.release-bot.storage.local]
path = "/var/lib/passless-agent/release-bot/credentials"
pin_path = "/var/lib/passless-agent/release-bot/pin"

[agents.profiles.release-bot.device]
name = "passless-agent-release"
phys = "release-phys"
uniq = "release-uniq"
vendor_id = 4660
product_id = 22137
```

A profile may mix behavior by RP and action. For example, it may allow authentication for a CI RP,
confirm registration for that RP, and deny both operations for every unmatched RP.

### One-shot operation binding

Every non-denied operation retains a one-shot intent record bound to the principal session,
endpoint, process identity, policy generation, action, exact RP ID, and credential reference where
applicable. `allow` automatically resolves that record; it does not bypass binding, policy
re-evaluation, credential scope, audit reservation, or terminal consumption.

An approval or policy decision cannot authorize another endpoint, RP, action, credential, policy
generation, or later operation. Browser leases do not provide reusable WebAuthn authority.

### Isolated mode

An isolated profile:

- Uses a distinct UHID endpoint and isolated credential/PIN namespace.
- Cannot enumerate or use human credentials.
- May deny, confirm, or allow registration and authentication independently for each RP.
- May use human or policy evidence according to the matched operation rule.
- Can be revoked locally and at the RP without revoking human credentials.

### Delegated-session mode

A delegated-session profile uses an ephemeral browser and a filtered view of explicitly configured
human credentials. Authentication may be denied, confirmed, or allowed. The one-shot grant remains
bound to one principal, endpoint, RP, credential, and policy generation and is consumed on every
terminal result.

Registration may also be denied, confirmed, or allowed, but requires an explicit registration
storage target. Writing to the human store requires `registration_storage = "human"`; omission
denies delegated registration. A delegated registration route may create a credential only for the
active exact RP and cannot enumerate, delete, manage, or access unrelated credentials.

The local browser lease controls the managed browser lifetime. It is not an RP token, continuing
WebAuthn authority, or proof of RP-side revocation.

## Operator authority

Agent policy is administrator-controlled and outside every principal boundary. The principal may
request an operation but cannot add or broaden a rule, select a different evidence source, change a
storage target, reload policy, or approve its own confirmation prompt.

Policy-authorized UP and UV are accepted machine-authorization semantics. They are suitable only
where the operator controls the profile and accepts that the RP receives ordinary WebAuthn flags
without learning whether their source was human or policy. RP-supported workload identity, service
accounts, and scoped OAuth remain preferable when available.

## Security goals

The implementation must:

- Preserve existing human behavior and keep agent support disabled by default.
- Structurally separate human and agent UHID routes.
- Keep private keys inside daemon-owned storage.
- Match exact current RP and action policy before every credential operation.
- Keep isolated credentials separate from human and other profile stores.
- Restrict delegated access to configured credentials and explicit registration targets.
- Distinguish human and policy UP/UV sources in protected audit.
- Re-evaluate policy before request binding, confirmation, automatic resolution, and key use.
- Durably reserve every credential creation or use before invoking credential callbacks.
- Fail closed on missing policy, routing, storage, audit, isolation, or required prompt controls.
- Preserve one-shot operation binding even when policy automatically authorizes a ceremony.

## Non-goals

The design does not:

- Modify browser WebAuthn behavior or use an extension, proxy, or patched browser.
- Let an agent export private keys, PINs, cookies, tokens, raw assertions, or arbitrary signatures.
- Make a delegated browser session independently identifiable or revocable at the RP.
- Restrict business actions performed after login.
- Claim that policy-authorized UP or UV represents ceremony-time human interaction.
- Protect against host root, kernel compromise, or a malicious Passless administrator.
- Distinguish subprocesses inside one authenticated principal boundary.

## Normative invariants

1. Agent support is disabled unless an administrator enables it.
2. Missing or invalid rules deny; unknown modes and enum values fail configuration.
3. Human and agent requests use distinct UHID endpoints with kernel-enforced visibility.
4. Every endpoint is bound to one authenticated profile, principal session, and policy generation.
5. Passless exactly matches the CTAP RP ID and action to one current rule.
6. The principal cannot modify policy or select an evidence source at request time.
7. `deny` performs no prompt and no credential access.
8. `confirm` requires one fresh trusted approval for the exact operation.
9. `allow` may skip the prompt but never skips one-shot binding, audit, scope, or consumption.
10. Human UP is produced only by the bound confirmation; policy UP only by an explicit rule.
11. Human UV is produced only by actual local verification; policy UV only by an explicit rule.
12. Audit records distinguish human, policy, and absent evidence.
13. Isolated credentials remain unavailable to human and other agent endpoints.
14. Delegated authentication exposes only the configured exact credential and RP.
15. Delegated registration requires an explicit target and is scoped to the active exact RP.
16. Delegated registration cannot imply enumeration, deletion, management, or arbitrary writes.
17. Policy changes invalidate pending intents, grants, authorizations, and affected leases.
18. Every terminal result consumes the bound operation authority.
19. A browser lease cannot authorize another WebAuthn operation.
20. No credential creation or use occurs without a durable pre-execution audit reservation.
21. Private keys and secret material never cross principal, CLI, audit, or ordinary environment
    boundaries.
22. Agent failure does not weaken or stop the human authenticator path.

## Threat model

| Threat | Required mitigation | Residual risk |
|---|---|---|
| Malicious page requests another RP | Browser origin checks plus exact CTAP RP policy | Passless cannot display the independently verified exact origin |
| Principal broadens automatic authority | Operator-owned policy and authenticated principal boundary | Host administrator remains trusted |
| Policy UP/UV is mistaken for human evidence | Explicit configuration, audit source, and documentation | RP sees only standard flags and cannot distinguish the source |
| Automatic registration creates uncontrolled credentials | Exact action rule, explicit target, durable audit, and scoped write | RP account policy controls resulting account authority |
| Agent selects another human credential | Exact delegated credential filter | Account labels remain untrusted |
| Another browser consumes authority | Dedicated endpoint and kernel device policy | Kernel/device-policy failure compromises routing |
| Repeated assertions occur during a lease | One-shot records and policy re-evaluation for every operation | Explicit `allow` rules can authorize each new operation |
| Agent suppresses audit | Audit outside principal and durable pre-write gate | Host root can rewrite local audit without external anchoring |
| Browser session exceeds intended action | Short lease and honest limitation | Passless cannot scope RP business actions |

## Honest security claims

Documentation and user interfaces must state:

- `allow` is autonomous WebAuthn authorized by administrator policy.
- Policy-authorized UP/UV is not ceremony-time human interaction or local human verification.
- RPs receive ordinary WebAuthn flags and generally cannot distinguish their source.
- Exact RP restriction applies to the WebAuthn operation, not later browser actions.
- Delegated mode lets the principal act with the RP authority of the selected human account.
- Local lease expiry is not RP-side session revocation.
- RP-supported agent credentials are preferable when actor, scope, and revocation matter.

## Consequences

### Positive

- One profile can combine denied, supervised, and unattended operations.
- Production and validation no longer require debug auto-approval for explicitly autonomous rules.
- Registration and authentication policy is exact and independently reviewable.
- Credential ownership remains separate from interaction policy.
- Existing endpoint, one-shot state, storage, and audit architecture is reused.

### Negative

- Policy-authorized UP/UV intentionally weakens their ordinary human-evidence interpretation.
- A mistaken `allow` rule can create or use credentials without a contemporaneous human decision.
- Delegated automatic use grants the principal the selected human account's RP session authority.
- Delegated writes increase the shared-store attack surface and require additional synchronization.
- Configuration, audit review, and release validation become more complex.

## Alternatives considered

### Keep mandatory confirmation

Rejected. It prevents intended unattended operation and encourages test-only bypasses that do not
exercise real production policy.

### Add a third autonomous mode

Rejected. Credential ownership and interaction policy are independent. A third mode would duplicate
isolated and delegated storage and endpoint behavior and prevent mixed RP policies.

### Treat `allow` as authorization but return no UP/UV

Rejected as the only autonomous behavior. Many browser/RP ceremonies require these flags. Operators
instead choose the evidence source explicitly and accept its semantics.

### Use wildcard or suffix RP rules

Rejected. Exact RP policy is easier to audit and avoids unintended authority over sibling hosts.

## Rollout and rollback

The schema change is experimental and intentionally fail-closed. Existing supervised-only profile
configuration must be migrated to explicit rules before enabling agents. Policy digest versioning
invalidates all in-memory intents, grants, and leases during upgrade.

Rollback disables agent profiles, destroys endpoints, revokes one-shot state and leases, terminates
managed browsers, and preserves audit evidence. Human credentials and configuration remain usable.

The feature remains best-effort until the deterministic suite, recorded release-lab run, and
independent security review have no unresolved release blocker.
