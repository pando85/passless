# Roadmap: policy-controlled password use by agents

> **Status: Proposal (not implemented).** This document scopes a possible extension to the
> experimental Passless agent subsystem. Examples below are **design sketches**, not supported
> configuration, commands or MCP tools. No implementation is authorized by this document.

## Context

Passless v0.22.0–v0.27.0 introduced managed-browser agent delegation, principal sessions,
per-RP `deny`/`allow`/`request` rules, escalation and pre-requests, persistent grants, policy
revocation and an audit-before-use gate. [ADR 0014](../decisions/0014-agent-delegation.md)
defines the existing WebAuthn threat model.

An agent sometimes needs a traditional password from a `pass` (password-store) repository
when a website cannot use passkeys, scoped OAuth, app installations or dedicated accounts.
The current `pass` storage adapter is a **FIDO credential adapter**, not a general
password-reading API: it decrypts `fido2/*.gpg` and parses FIDO credential records.
It should not be exposed to agents as a generic decryption method.

**Proposed direction:** add a deliberately narrow password-use capability to the existing
Passless agent broker, reusing authorization infrastructure but keeping the password-specific
delivery and leakage risks explicit. Prefer RP-native OAuth/service accounts where feasible.

## Goals and non-goals

Goals:

- Permit an explicitly configured agent to **request approval to fill one selected password**
  from an operator-controlled `pass` store into a managed browser.
- Enforce default deny, exact secret identity, explicit destination allowlists, operation type,
  principal/session binding, limited uses, bounded TTL, revocation and durable audit.
- Avoid placing plaintext password values in MCP/CLI responses, audit records, logs or
  agent-visible tool results on the initial path.
- Preserve existing human UHID/FIDO2 behavior and the current agent passkey protocol unless an
  intentionally versioned extension is required.
- Keep plaintext decryption restricted to the broker's trusted execution boundary.
- Support distinct-UID deployments where agent processes cannot read the password store,
  control the GPG agent, modify policy or approve their own notifications.

Non-goals for the initial release:

- Arbitrary `pass show`, generic decrypt, bulk export or a `get_secret` MCP tool.
- Password creation, mutation, rotation, deletion, TOTP, credit cards or SSH keys.
- Wildcard secret paths, wildcard destination sites, dynamic mapping of arbitrary sites to secrets,
  cross-origin frames or unattended account enrollment.
- A claim that filled passwords are cryptographically non-exportable: they are **not**.
- Preventing agent actions once the destination site issues an authenticated browser session.
- Protecting against compromised daemon/root/kernel or an agent with the daemon's Unix identity.

## Core security distinction

| Capability | Passkey / WebAuthn | Traditional password |
| --- | --- | --- |
| Broker operation | Sign a scoped challenge | Decrypt and deliver a reusable bearer secret |
| Private material remains in broker | Yes (subject to key provider) | Not end-to-end: password must reach the site |
| Current agent-facing interface | WebAuthn proxy in managed browser | None; proposed controlled fill |
| After authentication | Agent controls the site's logged-in session | Same, plus password may be recoverable from the browser |
| Local revocation | Stops new broker operations | Cannot recall a password already observed or copied |

**Important limitation:** The current Playwright/CDP agent can inspect and execute JavaScript in
its browser. Even if a `fill` tool never returns plaintext in a tool response, the agent
can read a filled input value (or observe/retain it through other browser capabilities).
CDP `pipe` is not a confidentiality boundary when arbitrary browser evaluation remains
available; CDP `port` is even broader. A form-fill MVP provides controlled access and
auditable disclosure, **not secrecy against a malicious agent that controls the browser**.
Do not describe it as 'password never reaches the agent' or as equivalent to non-exportable signing.

A future stronger browser boundary would require a separately evaluated constrained automation
surface with no general DOM/JS/CDP escape, plus careful analysis of page-controlled exfiltration
and authenticated sessions. Do not silently inherit the WebAuthn threat model.

## Proposed architecture

```text
 Agent principal (separate Unix UID for real enforcement)
      | principal-scoped CLI / MCP request
      v
 Passless daemon: authenticate principal, resolve secret policy
      |         |                     |
      |         +--> approval/grants  +--> audit-before-use
      |
      +--> PassSecretStore (read-only, scoped, GPG-backed)
      |         |
      |         +--> operator-owned password-store (.gpg files)
      |
      +--> managed browser bridge (verified destination origin)
                |
                +--> selected password input (plaintext exposure boundary)
```

**Reuse** the principal identity/session machinery, escalation and cooldowns, pre-request
pattern, policy generations, revocation, limits, and audit. Add a **separate** secret action
namespace, typed grant payloads and a secret-specific fulfillment path.

Suggested internal boundaries:

- `SecretRef`: opaque/stable identifier for a configured `pass` entry; agents cannot
  supply arbitrary filesystem paths. No enumeration beyond administrator-configured references.
- `PassSecretStore`: read-only, non-FIDO API; resolves a configured relative path below a
  fixed store root, decrypts only the chosen regular `.gpg` file, and extracts only the
  password line (optional username mapping must be explicit).
- `SecretPolicy`: evaluates profile, operation (`fill` initially), exact secret ref,
  exact HTTPS origins, browser lease, principal session, usage budget, TTL, policy generation and
  request/grant state.
- `SecretDelivery`: first iteration performs one approved browser fill; it must never
  supply decrypted bytes through the MCP transport or ordinary CLI output.
- `SecretAudit`: records request, decision, reservation, terminal result and revocation,
  without values or page data.

The existing `pass` adapter, GPG recipient handling and Git synchronization can inform
the design, but the FIDO credential cache and parser should not be repurposed for ordinary passwords.
Reads must not commit, push, rewrite or synchronize a password-store repository.

## Proposed policy shape (illustrative only)

```toml
[agents.profiles.coding]
mode = "same-user"                    # WebAuthn identity mode; NOT filesystem isolation
principal_user = "coding-agent"       # must differ from broker/approval UID for enforcement
max_session_ttl = 900
max_operations = 20

[agents.profiles.coding.secrets]
enabled = true
provider = "pass"
store_path = "/home/alice/.password-store"  # owned/accessible to broker, not agent

[[agents.profiles.coding.secrets.rules]]
id = "github-login"                   # configured stable ref; no arbitrary agent paths
path = "work/github"                  # relative to store root, no .gpg suffix
origins = ["https://github.com"]      # exact, HTTPS; browser-derived at time of fill
fill = "request"                      # deny | request | allow
max_uses = 1
approval_ttl_secs = 300
```

This syntax requires a new schema and validator. In particular, agent `mode = "isolated"`
is a credential-namespace choice, **not** an OS permission boundary. Secret-store authorization
must be independently configured, and neither same-user nor isolated mode must automatically
grant access to the human password store.

Policy decisions to settle before implementation:

1. Whether the password identity is a configured stable ID alone or a stable ID plus a
   daemon-resolved relative path (recommended: both, no path accepted from the principal).
2. Whether an approval lasts for **one fill** (recommended default) or a bounded session.
   Unlike existing passkey `Allow always` grants, do not create permanent password grants
   on click; permanent unattended access must be an explicit configured `allow`.
3. How password/username fields are mapped safely. Initially fill only an unambiguous,
   visible top-level password field at an exact approved origin; reject ambiguity.
4. Whether only explicit HTTPS origins are permitted in v1 (recommended) and how redirects
   invalidate any pending delivery.
5. Whether a strong containment mode is required for the MVP release or the MVP is explicitly
   described as security-limited on shared-UID systems.

## Proposed operator and agent interface (not implemented)

```text
passless agent request-secret-access github-login --profile coding --action fill
passless agent-admin secret-grants list --profile coding
passless agent-admin secret-grants revoke --profile coding --id github-login
```

Potential opt-in MCP tools:

- `passless_request_secret_access`: request a scoped approval. Return only the decision,
  status and non-secret ref; an agent note is untrusted audit metadata, never prompt authority.
- `passless_fill_password`: complete a single, preauthorized fill into a verified managed
  browser; do not accept a raw password or return one.

Avoid auto-discovering or exposing a list of all password filenames: secret names can be sensitive.
Any credential availability response should disclose at most configured references.

Approvals must use daemon-owned information and the existing trusted-notification boundary.
On shared UID, an agent can control its own D-Bus notifications, GPG agent and password store;
advertise the limitation and fail closed if a profile requires strong isolation but lacks it.
Pre-approval is **not** permission to fill anywhere: re-check the live policy and browser-provided
origin at use time. Bind the one-use authorization to the exact secret ref, action, profile,
principal session, browser lease, origin, expiry and policy/revocation epoch.

## Delivery and storage hardening

- Require an explicit secret root; refuse overlap with Passless's FIDO2 credential area,
  agent state and audit data. Never infer a plaintext secret permission from a WebAuthn rule.
- Confine lookups beneath the root, reject absolute paths, `..`, symlink traversal,
  special files and hard-to-verify filesystem races; open-and-verify the target securely.
- Keep decryption keys and GPG-agent sockets unreachable by the principal. A different
  `principal_user` alone is insufficient if mounts, groups, sockets or home permissions
  still permit bypass. Test these boundaries explicitly.
- Respect existing `pass` GPG recipient semantics for decryption; do not reinterpret
  `.gpg-id` as an authorization mechanism.
- Minimize decrypted buffer lifetime; avoid persistent plaintext cache, argv/env injection,
  stdout, exceptions containing values, debug captures, traces, screenshots or audit data.
  Memory locking/zeroization are defense-in-depth, not guarantees against root.
- Bind the delivery to a trusted, verified browser destination. Reject unexpected frames,
  navigation between approval and fill, ambiguous fields, missing interception/lease
  evidence, and mismatched origins. Recheck immediately before decrypt/fill.
- Audit and fsync an allow/reservation before decrypting; fail closed when audit cannot
  commit. Record terminal status and reason without secret values.
- Bound concurrent requests, approval lifetime, request floods, and operation budgets.
  Revoke outstanding grants on policy changes and secret removal/rotation where detected.
- Clearly document that revocation ends **future fills**, not existing copies or remote login
  sessions; password rotation and RP logout are external procedures.

## Phased roadmap and acceptance criteria

### P0 — Threat model and design (blocking)

Deliverables:
- Proposed ADR describing secret-specific operations, principal/daemon/browser/page trust
  boundaries, GPG-agent exposure, approval semantics and explicit residual exfiltration paths.
- Decide the supported containment level and the threat claims for v1.
- Document example config and validation rules; keep feature off by default.

**Exit:** maintainers approve the boundary and wording; no claim of WebAuthn-equivalent
confidentiality or fully non-exportable passwords.

### P1 — Read-only `pass` secret store and policy

Deliverables:
- Typed `SecretRef` and explicit binding to configured `pass` entries.
- Read-only decrypted entry handling with hardened path confinement and strict password-line
  parsing; no cross-scope FIDO credential leakage.
- Secret rules, default-deny resolution, exact-origin matching, policy-digest integration,
  config check/doctor coverage and unit tests.
- Clear decision on separate versioned password grants instead of silently changing existing
  WebAuthn grants semantics.

**Exit:** agent can neither list arbitrary entries nor receive plaintext; all invalid paths,
duplicate rules, origin mismatches and inaccessible stores fail closed without decryption.

### P2 — Scoped approval, pre-request and audited browser fill

Deliverables:
- One-use `request` approval through the existing trustworthy prompt service.
- Session/lease/origin-bound and time-bounded fill capability, with one-time consumption,
  race-safe revocation and audit-before-decrypt.
- Opt-in CLI and MCP tools; access-request status returns non-secret information only.
- An operator path to inspect/revoke password-specific grants, independent of passkey grants.

**Exit:** a test site can authenticate with an explicit secret using one permitted fill;
denied/expired/revoked requests do not decrypt; the same approval cannot be replayed.

### P3 — Integration, negative tests and operator docs

Deliverables:
- Linux distinct-UID tests for filesystem and GPG-agent separation; notification self-approval
  and store access tests for shared UID with explicit expected limitations.
- Browser tests for redirect, origin change, iframe, hidden/ambiguous inputs,
  navigation races, browser teardown, revocation and policy reload.
- MCP/CLI redaction tests for tool outputs, errors, logs, audits, debugging and cancellation.
- Docs: quick start, threat model and limitations, configuration, upgrade/migration,
  backup/restore and an honest operational security checklist.

**Exit:** no unauthorized decrypt/fulfillment in the negative test matrix; security review
acknowledges that a CDP-capable agent can still recover filled passwords.

### P4 — Optional future extensions (separate decisions)

- Constrained browser automation exploration if a stronger password-confidentiality claim is
  desired; keep separate from the initial fill feature and do not assume it is solved.
- Scoped plaintext delivery to **trusted** workloads/CLI tools, with distinct policy actions,
  explicit approval and a stronger threat review.
- Username/TOTP support, mutation/rotation, alternative secret stores (e.g. Vault) and native
  credential-manager integration, each requiring independent design and access controls.

## Suggested implementation touchpoints

These are candidate touchpoints, **not** a prescription to reuse FIDO-specific types blindly:

| Existing module | Proposed change |
| --- | --- |
| `passless-core/src/agent/config.rs` | Add opt-in secret config, strict validation, typed actions |
| `passless-core/src/agent/policy.rs` | Include secret permissions in policy generation/digest |
| `passless-core/src/agent/protocol.rs` | Versioned principal secret requests/responses, no raw value API in MVP |
| `cmd/passless/src/agent/policy_engine.rs` | Resolve secret actions and enforce session/lease/TTL limits |
| `cmd/passless/src/agent/escalation.rs` | Bind one-use secret approvals; don't convert to indefinite passkey-style grants |
| `cmd/passless/src/agent/granted_rules.rs` | Prefer a separate typed/versioned secret-grant store or explicit safe migration |
| `cmd/passless/src/agent/audit*.rs` | Pre-decrypt audit reservation and secret-free terminal records |
| `cmd/passless/src/storage/pass/` | Extract reusable GPG plumbing; add a separate secret reader |
| `cmd/passless/src/commands/mcp_relay.rs` | Opt-in, typed MCP tools; no raw secret result |
| `cmd/passless/src/agent/browser.rs` | Broker-mediated, verified browser-fill path |
| `docs/agents/` | User-facing references only after implementation |

## Design questions to resolve

- Is a normal managed Chromium with arbitrary Playwright/CDP acceptable for the **audited
  disclosure** goal, or must the first release wait for a stronger browser-control boundary?
- Is one-use request approval sufficient for real workflows, and should session-scoped approval
  be an explicit follow-up rather than in v1?
- Should human and agent pass stores be required to use separate GPG key material and Git roots
  in hardened deployments?
- What is the safest supported password-field delivery mechanism under the current managed
  browser extension, especially for client-rendered forms?
- Which non-secret metadata can agents discover without leaking the password-store inventory?

## Related documents

- [Agent mode](../agents/README.md)
- [Rules and pre-requests](../agents/rules.md)
- [Containment](../agents/containment.md)
- [Security model](../agents/security.md)
- [ADR 0014: agent delegation](../decisions/0014-agent-delegation.md)
- [Password-store backend](../../cmd/passless/src/storage/pass/mod.rs)

**Status reminder:** this is a planning proposal. None of the password configuration, CLI,
MCP tools or browser-fill capabilities described here exists in v0.27.0.
