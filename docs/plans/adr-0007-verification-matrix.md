# ADR 0007 Verification Matrix

- **Status:** Proposed
- **Date:** 2026-08-06
- **Decision:** [ADR 0007](../decisions/0007-unified-agent-identity-modes.md)
- **Implementation plan:** [ADR 0007 implementation plan](adr-0007-agent-mode-redesign-implementation.md)

## Purpose

This matrix is the acceptance contract for the unified `same-user` and `isolated` agent modes. A row is not complete because code exists or a unit test passes. Its required evidence column defines the minimum proof.

Status values:

- `not-started`
- `in-progress`
- `blocked`
- `passed`
- `deferred` — allowed only for rows marked optional

All mandatory rows must be `passed` before `same-user` leaves its experimental gate.

## Configuration and trust boundary

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| C01 | yes | Agent support and same-user mode are disabled by default | Config unit test and integration startup test | not-started |
| C02 | yes | `mode = "same-user"` parses without profile storage | Config unit test | not-started |
| C03 | yes | Same-user rejects profile credential and PIN paths | Negative config integration test | not-started |
| C04 | yes | `mode = "isolated"` requires a complete profile backend | Negative and positive config tests | not-started |
| C05 | yes | Isolated storage cannot overlap human or another profile | Canonical-path overlap tests, including symlink cases where supported | not-started |
| C06 | yes | Missing RP/action policy denies | Unit and daemon integration tests | not-started |
| C07 | yes | `deny`, `autonomous`, and `supervised` normalize exactly as ADR 0007 defines | Parser table test | not-started |
| C08 | yes | Invalid authorization/evidence combinations fail startup | Exhaustive config matrix | not-started |
| C09 | yes | The effective config clearly identifies same-user as fully trusted | CLI/doctor snapshot test and documentation review | not-started |
| C10 | optional | Legacy `policy` evidence alias emits a deprecation warning and normalizes to `agent` | Parser and log test | not-started |

## Backend ownership and provider wiring

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| B01 | yes | Same-user receives the exact human backend handle | Integration test comparing namespace, provider, and lock identity | not-started |
| B02 | yes | Isolated receives a distinct backend handle | Integration test | not-started |
| B03 | yes | Isolated code cannot resolve the human backend | Type/factory unit test and adversarial integration test | not-started |
| B04 | yes | Sign and register handlers do not open paths or choose providers | Code review checklist and architecture test where practical | not-started |
| B05 | yes | Software human backend remains software in same-user mode | Integration test | not-started |
| B06 | yes | Portable-TPM human backend remains TPM in same-user mode | TPM integration test | not-started |
| B07 | yes | Portable-TPM isolated backend remains TPM | TPM integration test | not-started |
| B08 | yes | Human and same-user operations share counter serialization | Concurrent integration test | not-started |
| B09 | yes | Independent isolated backends do not share a global operation lock | Concurrency test | not-started |
| B10 | yes | No backend handle, private key, PIN, or arbitrary-signing API appears in agent protocol or logs | Protocol review, secret-scanning test, and log assertions | not-started |

## Session lifecycle

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| S01 | yes | Session is bound to profile, mode, principal, browser runtime, extension instance, and policy generation | Unit and integration tests | not-started |
| S02 | yes | Session expires at configured TTL and cannot exceed daemon maximum | Deterministic-clock tests | not-started |
| S03 | yes | Session operation budget is enforced atomically | Concurrent test | not-started |
| S04 | yes | Explicit revoke prevents new operations immediately | Integration test | not-started |
| S05 | yes | Policy reload invalidates affected sessions | Integration test | not-started |
| S06 | yes | Browser shutdown invalidates its session | Browser E2E | not-started |
| S07 | yes | Principal/launcher death invalidates the session | Process integration test | not-started |
| S08 | yes | Daemon restart invalidates all in-memory sessions | Restart integration test | not-started |
| S09 | yes | Session capability is high entropy, redacted, and scoped to one session | Unit entropy/format test and log assertions | not-started |
| S10 | yes | Session registry is bounded and expired entries are cleaned | Load/unit test | not-started |

## One-shot operation authority and replay resistance

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| O01 | yes | Every `get()` and `create()` call creates a distinct operation intent | Protocol integration test | not-started |
| O02 | yes | Operation binds session, action, RP, origin context, challenge, request hash, policy generation, and nonce | Unit serialization/hash test and integration assertion | not-started |
| O03 | yes | Exactly one concurrent submission reaches key use | Race test with instrumented provider | not-started |
| O04 | yes | Replay after success fails | Integration and browser E2E | not-started |
| O05 | yes | Replay after policy denial fails | Integration test | not-started |
| O06 | yes | Replay after cancellation fails | Browser E2E | not-started |
| O07 | yes | Replay after timeout fails | Browser E2E | not-started |
| O08 | yes | Request hash mismatch fails before credential access | Negative integration test with storage access spy | not-started |
| O09 | yes | Policy change between authorization and key use fails | Synchronization/race integration test | not-started |
| O10 | yes | Every terminal path consumes the operation | State-machine property test and failure injection | not-started |
| O11 | yes | Operation/replay registries remain bounded | Load test | not-started |

## Authorization and evidence

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| E01 | yes | `authorization = allow` skips human approval but still evaluates all operation gates | Integration test with gate spies | not-started |
| E02 | yes | `authorization = confirm` requires one operation-bound human approval | Human-interaction integration test | not-started |
| E03 | yes | `authorization = deny` performs no credential access and no human prompt | Negative test with storage/UI spies | not-started |
| E04 | yes | RP-required UV alone never sets UV | Regression unit and E2E test | not-started |
| E05 | yes | Agent UV requires successful bound agent-session verification | Unit and integration tests | not-started |
| E06 | yes | Human UV requires production human PIN/platform verification | Integration test | not-started |
| E07 | yes | Agent UP requires successful bound agent-session presence evidence | Unit and integration tests | not-started |
| E08 | yes | Human UP requires the bound human interaction path | Integration test | not-started |
| E09 | yes | Fully autonomous policy satisfies RP-required UV without human interaction | Real-RP E2E and audit evidence | not-started |
| E10 | yes | `user_verification = human` forwards verification and never exposes the PIN | E2E, protocol assertion, and secret log scan | not-started |
| E11 | yes | `user_verification = none` fails when RP or credential policy requires UV | Unit and E2E tests | not-started |
| E12 | yes | `preferred` and `discouraged` follow configured prompt preference | Policy table tests | not-started |
| E13 | yes | `credProtect` strengthens verification requirements | Credential-policy integration tests | not-started |
| E14 | yes | Audit distinguishes agent UV, human UV, and absent UV | Audit snapshot tests | not-started |
| E15 | yes | A human interaction result cannot authorize a later operation | Replay integration test | not-started |

## Credential discovery and selection

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| D01 | yes | Same-user can use an existing human credential without duplicating its ref in normal allow-list flows | Real-RP or faithful integration test | not-started |
| D02 | yes | `allowCredentials` order is respected among permitted credentials | Unit and integration tests | not-started |
| D03 | yes | Explicit credential ref narrows selection | Integration test | not-started |
| D04 | yes | Discoverable single candidate succeeds | Browser E2E | not-started |
| D05 | yes | Multiple candidates with `single` fail without key use | Negative E2E and storage spy | not-started |
| D06 | yes | `first-matching` is stable and only active when explicit | Deterministic selection test | not-started |
| D07 | yes | `newest` selects by persisted creation metadata | Unit and integration tests | not-started |
| D08 | yes | A selected credential must match exact RP and configured scope | Negative integration tests | not-started |
| D09 | yes | Page and agent cannot request unrestricted credential enumeration | Protocol/API review and negative test | not-started |
| D10 | yes | Isolated selection never returns a human candidate | Adversarial integration test | not-started |

## Authentication correctness

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| A01 | yes | Same-user software assertion verifies with existing credential public key | Cryptographic integration test | not-started |
| A02 | yes | Same-user portable-TPM assertion verifies | TPM integration/E2E | not-started |
| A03 | yes | Isolated software assertion verifies | Cryptographic integration test | not-started |
| A04 | yes | Isolated portable-TPM assertion verifies | TPM integration/E2E | not-started |
| A05 | yes | UP/UV bits equal resolved evidence and no other source | Byte-level authenticator-data tests | not-started |
| A06 | yes | RP ID hash is correct | Byte-level test | not-started |
| A07 | yes | Client data type, challenge, origin, topOrigin, and crossOrigin are correct | Byte-level and browser E2E | not-started |
| A08 | yes | Signature counter increments once per successful returned assertion | Sequential and concurrent tests | not-started |
| A09 | yes | Counter persistence failure prevents returning success | Failure-injection test | not-started |
| A10 | yes | Unsupported required extension fails explicitly | Integration test | not-started |
| A11 | yes | Authentication audit is reserved before provider sign | Instrumented provider/audit ordering test | not-started |
| A12 | yes | Failure after audit reservation finalizes a terminal result | Failure-injection audit test | not-started |
| A13 | yes | Same-user existing credential succeeds against a real RP | Real-RP E2E | not-started |
| A14 | yes | Isolated credential continues to succeed against a real RP | Regression real-RP E2E | not-started |

## Registration correctness

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| R01 | yes | Same-user registration writes only to human backend | Integration test | not-started |
| R02 | yes | Isolated registration writes only to profile backend | Integration test | not-started |
| R03 | yes | Registration is denied unless exact RP rule explicitly allows it | Negative E2E | not-started |
| R04 | yes | Algorithm is selected from RP order and backend capabilities, not hardcoded | Parameterized unit/integration test | not-started |
| R05 | yes | No supported algorithm returns `NotSupportedError` before key generation | Provider spy test | not-started |
| R06 | yes | `excludeCredentials` is checked under lock immediately before creation | Concurrent race test | not-started |
| R07 | yes | Resident/discoverable requirements are honored | Registration integration tests | not-started |
| R08 | yes | Required UV uses configured agent or human evidence | Registration E2E | not-started |
| R09 | yes | Authenticator data includes correct AT, UP, UV, RP hash, AAGUID, credential ID, and COSE key | Byte-level test | not-started |
| R10 | yes | Unsupported attestation requirement fails without false claims | Integration test | not-started |
| R11 | yes | Software registration then authentication succeeds | Real-RP E2E in both modes | not-started |
| R12 | yes | Portable-TPM registration then authentication succeeds before TPM registration is advertised | TPM real-RP/manual release gate | not-started |
| R13 | yes | Provider generation followed by storage failure performs documented cleanup | Failure-injection test | not-started |
| R14 | yes | Registration audit is reserved before key generation | Ordering test | not-started |

## Origin, RP, frame, and transport security

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| X01 | yes | Valid HTTPS origin with explicit port is accepted | Unit and E2E test | not-started |
| X02 | yes | RP equal to origin effective domain is accepted | Unit test | not-started |
| X03 | yes | Valid registrable-domain suffix RP is accepted | Unit test | not-started |
| X04 | yes | Public suffix RP is rejected | Public-suffix fixture test | not-started |
| X05 | yes | Invalid IP/localhost cases follow documented policy | Unit tests | not-started |
| X06 | yes | Extension sender URL is primary and MAIN-world origin is cross-checked | Spoofing E2E | not-started |
| X07 | yes | Top-level frame requests succeed | Browser E2E | not-started |
| X08 | yes | Cross-origin frames fail closed until fully supported | Browser E2E | not-started |
| X09 | optional | Supported cross-origin iframe uses correct topOrigin and Permissions Policy | Multi-origin browser E2E | not-started |
| X10 | yes | Bearer never enters page-visible MAIN-world data or logs | Extension test and source review | not-started |
| X11 | yes | Missing, wrong, expired, or other-session bearer fails | HTTP integration tests | not-started |
| X12 | yes | Loopback ingress enforces body, concurrency, and protocol-version limits | HTTP integration/load tests | not-started |
| X13 | yes | Session bearer cannot bypass RP, operation, evidence, or audit checks | Adversarial integration test | not-started |

## Browser API and lifecycle compatibility

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| W01 | yes | Non-public-key Credentials API calls use the original browser API | Browser test | not-started |
| W02 | yes | Authentication and registration option serialization is lossless for supported fields | JS unit test with binary fixtures | not-started |
| W03 | yes | Abort before dispatch rejects with `AbortError` and creates no credential use | Browser E2E | not-started |
| W04 | yes | Abort during processing consumes operation and prevents later success | Browser/provider synchronization E2E | not-started |
| W05 | yes | Timeout uses the strictest applicable deadline | Deterministic browser/daemon test | not-started |
| W06 | yes | Tab/browser shutdown invalidates or consumes pending authority | Browser E2E | not-started |
| W07 | yes | Errors map to appropriate DOMException classes | Browser parameterized test | not-started |
| W08 | yes | Response exposes required fields and methods, including `toJSON()` and extension results | Browser compatibility test | not-started |
| W09 | yes | Multiple simultaneous frame requests cannot cross-correlate | Multi-frame race E2E | not-started |
| W10 | yes | Agent path never unexpectedly opens native security-key UI | Real browser E2E/manual visual assertion | not-started |
| W11 | optional | RP requiring native `instanceof PublicKeyCredential` works through an approved adapter | Compatibility E2E | not-started |

## Audit and observability

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| L01 | yes | Audit reservation failure prevents storage or key-provider access | Failure-injection test | not-started |
| L02 | yes | Every terminal operation has a finalized audit result | State-machine/audit property test | not-started |
| L03 | yes | Audit contains mode, namespace, profile, principal, RP, origin context, action, policy generation, selection, evidence sources, result, and counter metadata | Snapshot tests | not-started |
| L04 | yes | Audit does not contain key material, PIN, bearer, raw assertion signature, or unrestricted user secrets | Secret scan and snapshot tests | not-started |
| L05 | yes | Same-user autonomous events are unmistakably labeled | Snapshot and operator UX test | not-started |
| L06 | yes | Metrics use bounded labels and exclude RP, origin, credential, session, and operation identifiers | Metrics review/test | not-started |
| L07 | yes | Replay, expiry, cancellation, audit failure, and provider failure are separately observable | Metric/log integration tests | not-started |
| L08 | yes | Diagnostics show selected backend/provider without revealing secrets | Doctor snapshot test | not-started |

## Isolation and adversarial tests

| ID | Mandatory | Requirement | Required evidence | Status |
|---|---:|---|---|---|
| I01 | yes | Isolated profile cannot authenticate with a known human credential ID | Adversarial integration/E2E | not-started |
| I02 | yes | Isolated profile cannot register into human backend | Adversarial integration test | not-started |
| I03 | yes | Same-user profile cannot escape configured exact RP rules | Adversarial E2E | not-started |
| I04 | yes | Credential ref for another RP is rejected before key use | Negative integration test | not-started |
| I05 | yes | Policy reload narrowing credentials invalidates pending operations | Race integration test | not-started |
| I06 | yes | A page cannot alter origin, RP, action, or challenge after operation binding | Mutation/race browser test | not-started |
| I07 | yes | Local caller with stolen request body but no valid session binding fails | HTTP adversarial test | not-started |
| I08 | yes | A session for one profile cannot call another profile's backend | Adversarial integration test | not-started |
| I09 | yes | Human authenticator remains available when agent runtime or extension fails | Human-path regression E2E | not-started |
| I10 | yes | Same-user threat statement is present in generated examples and CLI acknowledgement | Documentation/CLI test | not-started |

## Real-RP release scenarios

| ID | Mandatory | Scenario | Required evidence | Status |
|---|---:|---|---|---|
| P01 | yes | Same-user autonomous authentication with existing human passkey and username-first allow list | Captured E2E command, RP success, daemon audit | not-started |
| P02 | yes | Same-user autonomous discoverable authentication with one candidate | Captured E2E and audit | not-started |
| P03 | yes | Same-user autonomous RP-required UV | Captured E2E proving no human prompt and agent UV audit | not-started |
| P04 | yes | Same-user human-forwarded UV | Captured E2E proving human prompt and human UV audit | not-started |
| P05 | yes | Isolated autonomous authentication regression | Captured E2E and audit | not-started |
| P06 | yes | Same-user software registration followed by authentication | Captured E2E and human-store inspection | not-started |
| P07 | yes | Isolated software registration followed by authentication | Captured E2E and isolated-store inspection | not-started |
| P08 | yes | Replay captured browser request | Captured failure and no counter/key reuse | not-started |
| P09 | yes | Browser cancellation during authentication | Captured `AbortError`, consumed operation, audit | not-started |
| P10 | yes | Valid origin with non-default port | Captured RP success | not-started |
| P11 | yes | Portable-TPM same-user authentication before TPM support claim | Captured E2E, TPM provider evidence, audit | not-started |
| P12 | yes | Portable-TPM isolated authentication before TPM support claim | Captured E2E, TPM provider evidence, audit | not-started |
| P13 | optional | Portable-TPM registration in both modes | Captured E2E and cleanup validation | not-started |
| P14 | optional | Approved cross-origin iframe ceremony | Multi-origin E2E and clientData inspection | not-started |

## Exit gates by rollout phase

### Gate A: Unified isolated pipeline

Required rows:

- all `C` rows except optional aliases;
- `B02` through `B05`, `B07`, `B09`, `B10`;
- all mandatory `S`, `O`, and `E` rows applicable to isolated;
- `A03`, `A05` through `A12`, `A14`;
- `R02` through `R10`, `R14` if registration is migrated;
- mandatory top-level origin/browser/audit rows;
- `I01`, `I02`, `I08`, `I09`;
- `P05` and `P07` when registration is enabled.

### Gate B: Experimental same-user authentication

Required rows:

- all mandatory configuration/backend/session/operation/evidence rows;
- all mandatory discovery and authentication rows except TPM rows if TPM remains explicitly unadvertised;
- all mandatory origin/browser/audit/isolation rows;
- `P01` through `P05`, `P08`, `P09`, and `P10`.

### Gate C: Same-user registration

Required rows:

- all mandatory registration rows except portable-TPM registration if explicitly unadvertised;
- `P06` and `P07`;
- adversarial registration and audit rows.

### Gate D: Portable-TPM support claim

Required rows:

- `B06`, `B07`;
- `A02`, `A04`;
- `P11`, `P12`;
- `R12` and `P13` only if TPM registration is advertised.

### Gate E: Remove experimental flag

Required rows:

- every mandatory row is `passed`;
- optional rows are either `passed` or explicitly documented as unsupported;
- security review confirms no isolated-to-human backend path;
- operator documentation and migration notes are complete;
- old contradictory implementation paths are removed or disabled by an explicit compatibility policy.

## Evidence recording

When a row passes, update this file with:

- `passed` status;
- test name and path;
- CI run or commit reference;
- manual E2E date and environment where applicable;
- limitations or backend-specific scope.

Do not mark a row passed based solely on an implementation claim in a PR description.
