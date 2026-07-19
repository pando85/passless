# Agent ADR validation closure plan

- **Status:** Agreed implementation plan
- **Date:** 2026-07-18
- **Owners:** Passless maintainers
- **Covers:** Remaining engineering validation for [ADR 0001](../decisions/0001-agent-authentication-security-model.md), [ADR 0002](../decisions/0002-native-webauthn-agent-architecture.md), and the [agent authentication implementation plan](agent-passkey-implementation.md)
- **Validation claim:** Best-effort evidence on one recorded x86_64 Linux release-lab environment

Implementation lives in `tools/agent-validation/`. `make test-agent-validation` runs the deterministic CI subset; `tools/agent-validation/run.sh --release` remains the required local browser and privileged evidence gate. A required `SKIP` is `INCOMPLETE`, not completion evidence.

## Purpose

The agent implementation has broad unit and integration coverage, but the ADR exit gate also requires evidence at real process, browser, kernel, and deployment boundaries. This plan closes those engineering gaps without expanding the product design or duplicating existing backend tests.

The work is complete when one orchestrated release-lab run proves the supported agent flows on a recorded x86_64 Linux environment, all deterministic CI suites pass, and every remaining requirement is either backed by evidence or identified as an explicit limitation.

## Agreed constraints

- Use one suitable x86_64 Linux host rather than claiming a broad distribution matrix.
- Require systemd, udev, cgroup v2, UHID, hidraw, Unix users and groups, D-Bus, and stock Chromium on that host.
- Record the exact distribution, kernel, Chromium, systemd, libc, and package versions for each run.
- Treat a passing run as evidence only for the recorded environment.
- Keep privileged validation in a manually invoked release lab, not privileged CI.
- Run the privileged lab for every release candidate containing the agent feature.
- Automate the production prompt path in two layers: a deterministic D-Bus service and a real notification daemon in a virtual desktop session.
- Use Chromium as the only browser in the initial validation scope.
- Keep resource and fault testing deterministic and bounded; do not require open-ended soak tests.
- Store generated evidence locally under `target/agent-validation/`; do not commit or publish it by default.
- Use swtpm for TPM composition tests. Hardware TPM validation remains optional because the TPM adapter already has its own implementation and test strategy.
- Do not schedule independent security review in this plan. Until community review occurs, describe the result as best-effort and do not claim independent audit or formal security certification.
- Treat completion of this plan as engineering closure only; it does not satisfy the ADR's formal independent-review release gate.

## Non-goals

- Supporting or validating every Linux distribution, kernel, architecture, or browser.
- Adding Firefox coverage to the first complete pipeline.
- Reimplementing local, pass, or TPM storage backends.
- Repeating every backend test through every agent mode.
- Requiring physical TPM hardware.
- Creating a hosted privileged runner.
- Persisting raw CTAP payloads, credentials, PINs, cookies, capabilities, or private data as evidence.
- Treating browser-lease expiry as RP-side session revocation.
- Removing the experimental or best-effort qualification based on this work alone.

## Pain points and decisions

| Pain point | Decision |
|---|---|
| Existing browser tests use debug auto-accept | Exercise explicit `allow` rules and `DesktopPromptHandle` confirmation without debug bypasses |
| UP and UV are mostly verified by unit fixtures | Assert flags at the UHID transport boundary and independently at the controlled RP |
| Device permissions have only dry-run evidence | Run real udev and cross-identity open probes in the release lab |
| Principal isolation is mostly unit-tested | Launch real principals and test UID, namespace, cgroup, socket, filesystem, device, and capability boundaries |
| Agent modes lack complete browser E2E | Run isolated and delegated ceremonies through a stock Chromium instance and dedicated agent endpoint |
| Backend adapters are already tested | Add only representative agent-composition tests for local, pass, and swtpm |
| Required fault suites are broader than current system tests | Add bounded process, resource, storage, audit, and cleanup scenarios with explicit invariants |
| Full log secret scanning is pending | Capture test-run output and scan it against forbidden values and field classes |
| Install and uninstall are documented but unrehearsed | Exercise installation, disablement, cleanup, rollback, and human-authenticator continuity in the lab |
| Validation currently requires many commands | Provide one fail-closed orchestrator with preflight, cleanup, resume, and local reporting |

## Validation architecture

### Tier 1: Deterministic automated tests

Tier 1 runs without modifying host users, groups, udev rules, or system services. It belongs in normal CI where dependencies are available and must also run from the release orchestrator.

It includes:

- Existing formatting, Clippy, unit, integration, and documentation checks.
- Production prompt protocol tests against an isolated D-Bus notification service.
- Agent policy, intent, grant, storage-scope, audit, browser-lease, and protocol suites.
- Test-only transport-boundary assertions for CTAP UP and UV bits without writing raw packets to disk.
- Captured-log secret scanning.
- Deterministic resource-limit and fault-injection tests that do not require root.

### Tier 2: Automated browser session

Tier 2 runs locally in an isolated D-Bus and virtual-display session. It uses a real notification daemon and stock Chromium, but remains fully automated.

It includes:

- Real `notify-rust` calls from the production `DesktopPromptHandle`.
- Real notification actions for approve and deny.
- A configured minimum review delay and tests for premature action, timeout, and closure.
- Controlled-RP registration and assertion verification.
- Isolated and delegated agent-mode browser ceremonies.
- Browser lease expiry, revocation, crash, and cleanup.

Tier 2 must not set `PASSLESS_E2E_AUTO_ACCEPT_UV` or `PASSLESS_E2E_AUTO_ACCEPT_STORAGE`. Test setup must initialize required state explicitly before the production process starts.

Use a separate production-path harness that asserts both variables are absent and runs a release build. Do not adapt the existing debug E2E harness in a way that could silently retain its auto-accept behavior.

### Tier 3: Privileged release lab

Tier 3 runs only after explicit operator confirmation on a disposable or recoverable x86_64 Linux environment. The unprivileged orchestrator may request credentials, but only narrowly scoped setup, probe, and cleanup helpers run as root. Browsers, principals, and the controlled RP never run as root.

It includes:

- Installation and activation of test udev, systemd, sysusers, and tmpfiles configuration.
- Separate daemon, human-browser, agent-principal, and agent-browser identities.
- Real hidraw and `/dev/uhid` open probes from every identity.
- Namespace, cgroup, socket, filesystem, process, capability, and profile-boundary probes.
- Cleanup, quarantine, uninstall, rollback, and human-authenticator continuity.

## Work packages

### 1. Orchestrator and evidence model

Create `tools/agent-validation/` with one entry point:

```text
tools/agent-validation/run.sh --release
```

The entry point must:

1. Refuse to run from an unsupported or dirty lab state unless an explicit recovery option is used.
2. Capture environment metadata before changing the host.
3. Create a `0700` output directory below `target/agent-validation/<run-id>/`.
4. Run stages in dependency order and stop on the first failed invariant.
5. Invoke privileged helpers individually rather than running the whole orchestrator as root.
6. Register cleanup traps before the first host mutation.
7. Preserve enough local state to resume cleanup after interruption.
8. Produce a machine-readable summary and a concise Markdown report.
9. Mark skipped stages distinctly from passed stages.
10. Return nonzero unless every required stage passed and cleanup completed.

Required commands:

```text
tools/agent-validation/run.sh --preflight
tools/agent-validation/run.sh --automated
tools/agent-validation/run.sh --release
tools/agent-validation/run.sh --cleanup <run-id>
```

The local report records:

- Git commit and feature set.
- Distribution, kernel, architecture, libc, systemd, udev, cgroup mode, Chromium, notification daemon, pass, GPG, and swtpm versions.
- Stage start, finish, status, and failure reason.
- Test counts and scenario identifiers.
- Sanitized device identities, UIDs, GIDs, namespace inodes, cgroup paths, file modes, and open-probe results.
- Cleanup and rollback status.

The report must never contain credential IDs, user handles, private keys, PINs, cookies, browser tokens, IPC capabilities, raw assertions, or raw CTAP payloads.

### 2. Production prompt automation

Add a test notification service implementing the subset of `org.freedesktop.Notifications` used by `notify-rust`.

The service must:

- Run on a private session bus.
- Advertise action and body capabilities accepted by `DesktopPromptHandle`.
- Capture the application name, summary, bounded body, and action identifiers.
- Emit approve, deny, close, timeout, and deliberately premature actions.
- Apply actions only to a notification matching the expected Passless application and run nonce.
- Expose structured observations to the test process without logging secrets.

Tests must prove:

- Trusted fields identify the profile, mode, operation, and exact normalized RP ID.
- Untrusted context cannot alter trusted labels or inject unbounded content.
- Approval before the minimum review delay fails closed.
- Approval after the delay authorizes only the active operation.
- Denial, closure, timeout, malformed capabilities, and notification-service failure deny the operation.
- Servers advertising only a default action, unknown capabilities, or no usable action support are rejected.
- An approval cannot be replayed for another operation, endpoint, RP, credential, or policy generation.

Add a second prompt suite using a real notification daemon in an isolated virtual display and D-Bus session. Drive its action interface automatically and repeat approve, deny, timeout, and minimum-delay cases. This layer validates compatibility with a real notification implementation while the first layer provides deterministic protocol coverage.

### 3. Truthful UP and UV evidence

Add a test-only observer at the UHID/CTAPHID response boundary. It may expose only:

- CTAP command class.
- Success or terminal error class.
- Parsed authenticator-data UP and UV bits.
- A test run and operation correlation identifier.

It must not expose or persist raw reports, signatures, credential IDs, user handles, PIN material, client data, or authenticator data.

Implement and review this observer as a standalone test-infrastructure deliverable before using it as evidence. Tests must prove that production builds contain no observer endpoint and that the observer's serialized schema cannot represent raw protocol fields.

For each successful ceremony, compare three independent observations:

1. The trusted prompt result and operation binding.
2. UP and UV bits observed at the transport boundary.
3. The controlled RP's verified authenticator-data flags and signature result.

Required scenarios:

| Scenario | Expected result |
|---|---|
| Fresh approval, UP required | Success with UP set |
| Fresh approval and actual UV, UV required | Success with UP and UV set |
| Denial | Terminal denial; no successful assertion |
| Prompt timeout or closure | Terminal denial; no successful assertion |
| Premature approval | Terminal denial |
| Stale or replayed approval | Terminal denial |
| Wrong RP, endpoint, credential, or policy generation | Terminal denial |
| Explicit policy evidence | Success only when the exact action rule selects policy UP/UV; audit records the source |

Actual UV must use the production CTAP PIN/UV path. A notification action alone must never be accepted as UV evidence.

### 4. Complete Chromium agent pipeline

Extend the controlled RP and browser harness to run the complete daemon-to-browser path with a fresh Chromium profile and a dedicated agent UHID endpoint.

#### Isolated mode

- Register one discoverable credential for an allowed RP.
- Authenticate with that credential.
- Reject an unlisted RP and a different profile.
- Prove the human endpoint and another agent profile cannot use the isolated credential.
- Revoke the isolated credential locally and prove later authentication fails.

#### Delegated-session mode

- Start with one existing human credential.
- Select one exact RP and credential through the trusted flow.
- Complete exactly one assertion through the delegated endpoint.
- Prove delegated registration follows its exact rule and storage target; enumeration, deletion,
  credential management, wrong targets, and lease-only authority are denied.
- Prove a different allowed RP or different human credential is still denied.
- Race two assertions and prove only one terminal result can consume the grant.
- Prove the shared credential counter is not lost during concurrent human and delegated attempts.
- Confirm endpoint drain and destruction after the terminal result.

#### Browser lease

- Clamp the requested lease to policy maximum.
- Terminate Chromium on expiry, explicit revocation, principal exit, and daemon shutdown.
- Detect browser crash and clean the profile.
- Quarantine the profile when deterministic cleanup failure is injected.
- Never reuse a quarantined or previously completed profile.
- Confirm documentation and output describe this as local browser termination, not RP session revocation.

### 5. Privileged device and principal isolation

Build on `tools/agent-uhid-feasibility/` rather than replacing it.

#### Device policy

- Install, reload, and trigger the test udev rules.
- Verify deterministic device tagging and hidraw ownership/mode.
- Verify the daemon identity can open `/dev/uhid`.
- Verify human and agent identities cannot open `/dev/uhid`.
- Verify the human browser can open only the human hidraw node.
- Verify each agent browser can open only its own agent hidraw node.
- Verify another agent profile cannot open that node.
- Repeat open probes after endpoint recreation to catch stale permissions or enumeration assumptions.
- Verify failed endpoint creation never falls back to the human endpoint.

#### Principal boundary

- Verify the principal's UID, GID, supplementary groups, process start time, namespaces, cgroup, and `NoNewPrivileges` state.
- Verify the principal cannot access the admin socket, audit files, human credential store, another profile store, `/dev/uhid`, human hidraw node, or another profile's hidraw node.
- Verify the principal can access only its expected control socket and profile resources.
- Verify the browser cannot access daemon-only storage or sockets.
- Attempt namespace, cgroup, process, file-descriptor, and process-group escapes and require fail-closed results.
- Verify session capabilities are absent from command lines, ordinary environment variables, proc metadata available to the principal, captured logs, and audit output.

#### Lab safety

- Require a preflight check and explicit confirmation before mutation.
- Snapshot relevant users, groups, udev rules, service state, and Passless paths.
- Record every resource created by the run.
- Remove only resources recorded in that run's state file.
- Refuse cleanup when state ownership or paths do not match expected safe prefixes.
- Verify no test device, process, mount, namespace helper, socket, user, group, rule, or runtime directory remains.

### 6. Backend composition and human regression

Do not create a new backend abstraction or duplicate backend conformance suites.

Run the existing backend tests, then add these representative agent-composition cases:

| Backend | Agent-specific evidence |
|---|---|
| Local | Isolated profile storage separation and delegated access through the shared human adapter |
| Pass | The same two cases using a fresh non-interactive test password store and GPG identity |
| TPM via swtpm | The same two cases using a disposable swtpm state directory |

Each composition case must prove exact RP and credential scoping, successful mutable counter persistence, cleanup, and no second backend instance for delegated human storage.

Run the complete existing human E2E suite with agent support compiled but `[agents].enabled = false`. Human startup and authentication must continue if agent configuration, prompt service, audit path, or privileged setup is unavailable.

### 7. Deterministic failure and abuse scenarios

Reuse existing unit fault injection where it proves the invariant. Add system scenarios only where process, kernel, or filesystem behavior matters.

Required bounded scenarios:

- Endpoint capacity reached and recovered after cleanup.
- Pending-request, prompt, and browser-process limits reached without unbounded allocation.
- Oversized and malformed IPC and CBOR inputs rejected before side effects.
- Principal, browser, worker, daemon, and notification service terminated at selected lifecycle states.
- Audit pre-write failure prevents key use.
- Terminal audit failure enters the documented fail-closed state.
- ENOSPC, read-only path, partial write, and cleanup failure produce bounded recovery behavior.
- Wall-clock changes do not extend monotonic intent, grant, or browser deadlines.
- Daemon restart loses in-memory authority and recovers durable state safely.
- Concurrent cancellation, policy reload, approval, and grant claim produce one deterministic winner and no later key use.
- Unknown modes fail configuration, missing rules deny, policy evidence requires an exact rule, and one browser lease cannot authorize later assertions without a new rule evaluation.

Every scenario must declare its resource ceiling, timeout, expected terminal state, and cleanup invariant. A test that hangs or exceeds its ceiling fails.

### 8. Full-run secret scan

The orchestrator must capture stdout, stderr, structured test output, selected journal records, audit output, browser launcher output, and generated reports into the private run directory.

Before each scenario, generate unique sentinel values shaped like every sensitive class, including capability, PIN, credential ID, user handle, client-data hash, cookie, token, and private-key material. The scan must fail if a sentinel or a forbidden structured field appears outside the in-memory test fixture.

Also scan for:

- Unredacted `Debug` output.
- Long hexadecimal or base64-like values in prohibited event fields.
- Secrets in process arguments and ordinary environment variables.
- Raw CTAP, WebAuthn, IPC, or credential payloads in evidence.

False-positive exceptions must be exact, documented field rules rather than broad regular-expression exclusions.

### 9. Installation, rollback, and uninstall rehearsal

The final release stage must:

1. Start from a functioning human authenticator and record a successful human assertion.
2. Install the agent service, tmpfiles, sysusers, udev policy, and one test profile.
3. Complete isolated and delegated validation.
4. Disable the profile and prove active intents, grants, endpoints, principals, and browser leases are cancelled.
5. Exercise normal cleanup and one deterministic quarantine path.
6. Uninstall all agent-specific host configuration and data created by the run.
7. Restart the human authenticator without migrating or rewriting its credentials.
8. Repeat the original human assertion successfully.
9. Verify the snapshot and final-state inventory differ only in explicitly allowed logs or package caches.

The rehearsal must never use a real user's production credential store. It must run with disposable test configuration and credentials while still proving that the separate human test store survives agent removal unchanged.

## Orchestrated release sequence

`tools/agent-validation/run.sh --release` executes:

1. Environment and safety preflight.
2. Baseline host snapshot and local evidence directory creation.
3. Formatting, Clippy, unit, integration, and documentation checks.
4. Deterministic D-Bus prompt and transport-flag suites.
5. Local, pass, and swtpm agent-composition suites.
6. Human regression with agent support disabled at runtime.
7. Virtual-display Chromium and real-notification-daemon pipeline.
8. Privileged udev and principal-boundary setup and probes.
9. Deterministic process, resource, audit, storage, and cleanup failures.
10. Full-run secret scan.
11. Disablement, uninstall, rollback, and human-continuity rehearsal.
12. Final cleanup inventory and local report generation.

Stages 8 through 11 require explicit confirmation. A skipped required stage makes the run incomplete rather than successful.

## Acceptance matrix

| Gap | Completion evidence |
|---|---|
| Production prompt | Both notification layers pass approve, deny, timeout, close, early-action, and service-failure cases without debug auto-accept |
| Truthful UP/UV | Prompt binding, transport-boundary bits, and controlled-RP verification agree; UV comes from CTAP PIN/UV |
| Agent browser pipeline | Isolated and delegated registration/assertion policies pass through dedicated agent endpoints in Chromium |
| Delegated restrictions | Registration, discovery, management, wrong tuple, replay, and second assertion fail in real ceremonies |
| Device isolation | Cross-identity open matrix proves each browser can access only its own hidraw endpoint and no browser can access `/dev/uhid` |
| Principal isolation | Real UID, namespace, cgroup, socket, filesystem, process, device, profile, and capability probes pass |
| Shared credential safety | Concurrent human/delegated assertion preserves serialization and counter integrity |
| Backend composition | Representative local, pass, and swtpm isolated/delegated cases pass without duplicating adapters |
| Human compatibility | Existing human E2E passes with agent compiled and disabled, before install and after uninstall |
| Lease cleanup | Expiry, revoke, crash, principal exit, daemon shutdown, cleanup, quarantine, and non-reuse pass |
| Audit and faults | Pre-write gate, terminal failure, recovery, rotation, restart, pressure, and bounded cleanup scenarios pass |
| Secret absence | Full captured-run scan finds no sentinels, forbidden fields, raw payloads, or process-metadata leaks |
| Autonomous scope | Exact `allow` rules skip prompts while retaining one-shot binding; unmatched actions, replay, and lease-only authority fail |
| Operations | Install, disable, rollback, uninstall, final inventory, and human continuity pass |

## Completion and claims

Engineering closure is reached when:

- Tier 1 is part of normal automated validation and passes.
- One complete Tier 2 and Tier 3 release run passes on the recorded x86_64 Linux environment.
- The acceptance matrix has no failed, skipped, or unexplained item.
- Cleanup returns the lab to its recorded baseline.
- The implementation plan links to the local run procedure and accurately reports remaining limitations.

A completed run supports this claim:

> The Passless agent implementation passed its automated and privileged best-effort validation suite on the recorded x86_64 Linux environment using stock Chromium and local, pass, and swtpm-backed storage.

It does not support claims of broad Linux compatibility, hardware TPM validation, formal verification, independent audit, protection from root or kernel compromise, or RP-side session revocation. Independent community review may be added later without blocking execution of this engineering plan.
