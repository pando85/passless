# ADR 0002: Native WebAuthn agent architecture

- **Status:** Accepted
- **Date:** 2026-07-13
- **Decision owners:** Passless maintainers
- **Implementation status:** Implemented, validation pending
- **Depends on:** [ADR 0001](0001-agent-authentication-security-model.md)
- **Implementation plan:** [Agent authentication implementation plan](../plans/agent-passkey-implementation.md)

## Context

ADR 0001 defines isolated credentials and short-lived delegated browser sessions without changing browser behavior. This ADR selects the local architecture that makes those modes distinguishable and enforceable.

The current Passless process owns one credential backend, one `AuthenticatorService`, one CTAPHID loop, and one UHID device. Storage is protected by an in-process mutex and an instance lock keyed by backend state. The current UHID helper also uses a fixed device identity. These assumptions are appropriate for one human authenticator but cannot safely classify concurrent human and agent traffic.

CTAP requests contain an RP ID and client-data hash, but not the browser process, exact web origin, agent principal, or local policy identity. A configuration flag applied to a shared endpoint therefore cannot securely decide whether a request is human or agent traffic.

## Decision summary

The first implementation will extend the trusted Passless daemon to own:

- The existing human UHID endpoint and human authenticator service.
- Zero or more short-lived agent UHID endpoints.
- One endpoint registry binding each agent endpoint to one authenticated principal, profile, mode, policy generation, and active intent or delegation grant.
- Human credential storage as the sole owner of existing user credentials.
- Separate isolated credential stores for isolated profiles.
- A filtered delegated credential view that exposes one exact human credential to one temporary agent service without copying key material.
- An exact-RP delegated registration scope when policy explicitly selects the human store.
- A trusted launcher, browser-lease manager, policy engine, prompt implementation, and protected audit writer.

The daemon creates each agent endpoint with a unique kernel-visible identity. Linux device permissions and the principal sandbox make that endpoint visible only to its associated browser. The agent browser cannot access the human endpoint, and ordinary human browser processes cannot access agent endpoints.

No extension, native host, WebAuthn proxy, injected script, or custom browser build participates in the ceremony.

## High-level architecture

```text
Human browser
    |
    v
human UHID worker -> human AuthenticatorService -> human credential store
                                                    ^
                                                    |
                                      exact delegated credential view
                                                    |
Agent browser                                      |
    |                                               |
    v                                               |
agent UHID worker -> agent ceremony service --------+
                          |
                          +-> policy and one-shot state
                          +-> trusted prompt
                          +-> protected audit
                          +-> isolated credential store (isolated mode only)
```

The daemon is the only process that can reach credential storage. Agent processes and browsers receive no storage path, key handle, raw assertion API, or generic signing API.

## Endpoint identity and routing

Each UHID endpoint has a daemon-generated endpoint ID and a unique kernel-visible device identity. The implementation must support a configurable or generated device name, physical path, unique identifier, vendor ID, and product ID sufficient for deterministic udev and sandbox rules.

The endpoint registry records:

```text
endpoint_id
profile_id
principal_session_id
mode
device_identity
policy_generation
state
created_monotonic
expires_monotonic
active_authorization_id
```

Endpoint states are:

```text
creating -> ready -> active -> draining -> destroyed
             |         |          |
             +-------> failed <----+
```

An endpoint becomes ready only after the daemon verifies the expected hidraw node, ownership, permissions, and sandbox visibility. A browser is not launched before readiness. Failure to establish deterministic device identity or visibility destroys the endpoint and aborts the principal session.

The endpoint ID, not a CTAP field or caller label, selects the profile and service. A request can never move from an agent endpoint to the human service or another profile.

## Daemon and worker model

The daemon retains exclusive ownership of configured credential backends and audit state. Each UHID endpoint runs an independent CTAPHID handler and authenticator service worker. Workers share only explicitly injected, synchronized services:

- Human delegated access uses a filtered view over the daemon-owned human storage lock.
- Isolated access uses the profile's separate credential and PIN state.
- Policy, authorization state, audit, and prompt services are daemon-owned.
- Human requests receive scheduling priority if a shared human credential is contended.

An agent worker cannot hold the human authenticator service mutex while waiting for policy, audit, or user interaction. Human and agent CTAPHID channel state, pending requests, callback state, PIN state, and iterators are never shared.

The implementation may require an upstream change or a narrowly scoped local change to `soft-fido2-transport` so each UHID device can carry a unique `phys` and `uniq` value. This change is a Phase 0 gate, not an assumed capability.

## Principal and launcher boundary

A trusted launcher creates one principal session for one configured profile. The secure initial Linux profile requires a separate Unix identity, container, or equivalent kernel-enforced boundary.

The launcher:

1. Authenticates to the administrative daemon channel.
2. Requests a profile session under current policy.
3. Creates an ephemeral runtime directory and browser profile owned outside the principal.
4. Creates a 256-bit random session capability and transfers it through an inherited protected channel.
5. Creates the cgroup, namespace, container, device policy, filesystem policy, and resource limits.
6. Requests the agent UHID endpoint and grants the browser access only to its resulting hidraw node.
7. Starts a stock browser with the ephemeral profile and without personal sync, extensions, or profile state.
8. Starts the agent process with access only to the agent control channel and approved browser-control interface.
9. Terminates the browser, endpoint, and process tree when the session expires, exits, or loses a mandatory control.

The daemon authenticates the principal with peer credentials, launcher session identity, sandbox identity, and the inherited capability. A copied capability outside the expected boundary is insufficient.

The browser profile directory, administrative socket, audit path, credential roots, `/dev/uhid`, unrelated hidraw nodes, and other principals' runtime directories are absent or inaccessible inside the principal.

Before launching the browser, the daemon durably records a daemon-owned runtime manifest containing the principal session, endpoint, browser PID, process start identity, cgroup or transient-scope identity, and profile path. It contains no capability or credential data. Startup recovery validates PID start identity and cgroup ownership before terminating confirmed orphan processes and quarantining their profiles. A PID match without start-identity confirmation is never killed.

## Policy model

Policy is deny-by-default and administered outside every principal. A profile policy includes:

```text
profile_id
enabled
mode
principal_identity
exact_rp_rules: register and authenticate -> deny | confirm | allow
up_source: human | policy
uv_source: human | policy | none
allowed_credential_refs (delegated-session only)
isolated_store (isolated only)
delegated_registration_storage (delegated-session registration only)
max_intent_ttl
max_grant_ttl
max_session_ttl
browser configuration
device isolation configuration
```

Rules are exact:

- RP IDs are normalized DNS names with no scheme, port, path, wildcard, or trailing dot.
- Public suffix RP IDs are rejected.
- Registration and authentication are separate actions in both modes.
- Each exact RP/action rule independently denies, confirms, or allows the ceremony.
- Policy-authorized UP and UV require explicit evidence-source configuration.
- A delegated policy names explicit credential references.
- The principal cannot create, broaden, reload, or revoke policy.
- Security-relevant unknown fields and enum values are rejected.
- Policy is re-evaluated before endpoint creation, request binding, prompt display, and key use.
- A policy change immediately cancels affected unbound and active authorization state.

The browser enforces whether an origin may request the RP ID. Passless independently requires exact equality between the CTAP RP ID and policy. Policy and audit must not describe this as independent origin validation.

## Isolated-mode authorization

An isolated-mode intent contains:

```text
intent_id
idempotency_key
profile_id
principal_session_id
endpoint_id
action: register | authenticate
rp_id
credential_ref (authentication only)
credential_namespace (registration only)
policy_generation
created_monotonic
expires_monotonic
untrusted_reason
```

Intent states are:

```text
waiting_for_request -> bound -> waiting_for_user -> executing -> completed
          |              |             |              |
          +--------------+-------------+------------> terminal_failure
```

Only one unbound intent and one active ceremony are permitted per endpoint. A bound intent is consumed by every terminal result. A retry requires a new intent.

The agent authenticator service uses a stable agent AAGUID documented before release. It owns separate callback, PIN, credential iteration, and storage state. Human credentials are not injected into this service.

## Delegated-session authorization

A delegated authorization record contains:

```text
grant_id
idempotency_key
profile_id
principal_session_id
endpoint_id
action: authenticate
rp_id
credential_ref
policy_generation
created_monotonic
login_expires_monotonic
requested_session_ttl
session_expires_monotonic (set after assertion completion)
untrusted_reason
```

Before its bound prompt is approved, the record is a pending delegation request with no key-use authority. Approval atomically creates the one-shot grant and supplies UP for the same bound CTAP operation.

The login deadline and browser-session deadline are separate:

- `login_expires_monotonic` is the short period in which the one permitted WebAuthn request may bind.
- `session_expires_monotonic` is the maximum local lifetime of the browser after a successful assertion.

The session lifetime cannot exceed current policy. The principal cannot extend either deadline. Wall-clock timestamps are recorded for operators, but monotonic time decides expiry.

Delegated authorization states are:

```text
waiting_for_request -> bound -> waiting_for_user -> executing -> assertion_complete
          |              |             |              |              |
          +--------------+-------------+--------------+----------> terminal_failure

assertion_complete -> browser_lease_active -> expired | revoked | browser_exited
```

The grant is consumed when the delegated assertion reaches any terminal result. `browser_lease_active` does not keep the credential authorization active. After the daemon successfully submits the terminal CTAP response to the UHID transport, the endpoint enters `draining`; later requests are rejected before callback dispatch. Phase 0 must determine the kernel event or bounded drain procedure that allows safe destruction without claiming that Passless can observe whether browser code consumed the response.

The browser may still reject the assertion or the RP may refuse to create a session. Passless cannot observe RP session issuance without browser or RP cooperation. The local browser lease therefore means only that the approved browser remains available until its deadline.

## Delegated credential view

Delegated use does not create a second copy of a user credential. The daemon creates a capability-scoped storage view over the existing human storage owner.

The view permits only:

- Reading the exact credential named by the active grant.
- Returning it only when its stored RP ID exactly matches the CTAP RP ID and grant.
- Persisting the resulting signature-counter update through the same serialized human storage owner while a per-credential operation lock covers the complete read-sign-update sequence.

The view rejects:

- Iteration beyond the exact credential.
- RP enumeration.
- Registration and writes of new credentials unless the active exact rule selects the human registration target.
- Credential deletion or management.
- Access after the grant is consumed, expired, revoked, or detached from its endpoint.
- Any credential or RP mismatch.

The implementation must not instantiate a second independent storage adapter over the same path. One daemon-owned adapter coordinates human and delegated operations. A per-credential operation lock spans the complete assertion mutation sequence so two services cannot read and update the same counter concurrently. Backends must commit replacement records atomically; a failed or conflicting update aborts the operation and follows the existing credential-recovery policy rather than returning an untracked success.

## User presence and verification

Authenticator flags come only from the exact action rule's configured evidence source.

Immediately before an isolated or delegated key operation, the daemon presents a trusted prompt outside the principal boundary. The prompt shows:

- Trusted profile identity.
- Trusted mode.
- Trusted exact RP ID.
- Trusted action and credential label where available.
- RP account text as untrusted data.
- Agent reason or requested URL as untrusted data.
- For delegated mode, the maximum local browser-session lifetime and the warning that the RP sees the user.

For `confirm`, approval is tied to the active endpoint and CTAP operation. For `allow`, current policy resolves the same one-shot operation without a prompt. Denial, timeout, prompt failure, cancellation, policy change, or revocation rejects affected work.

UP and UV use the evidence sources selected by the exact action rule. Human UP requires the bound confirmation and human UV requires actual local verification. Policy UP/UV is recorded as administrator-authorized machine evidence and must not be described as human interaction. If a required prompt mechanism cannot provide distinguishable approval and denial actions, the `confirm` operation fails closed.

## Browser lease and profile lifecycle

The delegated browser profile is new for each grant and contains no pre-existing cookies, sync state, extensions, saved passwords, or platform passkeys. Passless never copies the user's regular browser profile.

The browser lease manager:

- Starts the lease no earlier than successful CTAP assertion completion.
- Uses a daemon-owned monotonic deadline.
- Terminates the browser and principal access at expiry or revocation.
- Removes the ephemeral profile after browser termination.
- Records cleanup success or failure.
- Never reuses a profile whose cleanup did not complete.

The agent must not receive the profile filesystem path or a Passless API that returns cookies or tokens. However, browser automation can itself expose page state, cookies, storage, or session authority depending on the control interface and RP. The implementation and documentation must not claim that killing the browser cryptographically revokes material the principal managed to copy. Strong deployments should restrict the browser-control interface and principal egress, but these controls do not create RP-side revocation.

The RP may end its session before the local deadline. Passless treats a browser exit, authentication redirect, or agent-reported loss of session as a reason to terminate early, not as trusted proof of RP revocation.

## Audit

Every agent request, including denied requests, produces versioned audit events. Before creating or using a credential, the daemon durably appends an authorization reservation. Failure to append and synchronize that record blocks key use.

Audit events include:

- Principal, profile, endpoint, mode, policy generation, and authorization ID.
- RP ID, action, non-secret credential reference, and result.
- Prompt, UP, and UV outcomes.
- Grant and intent state transitions.
- Browser-lease creation, expiry, revocation, browser exit, and profile cleanup.
- Stable errors and wall-clock plus monotonic-duration information.

Audit events never include private keys, PINs, capabilities, cookies, tokens, raw assertions, client-data hashes, raw credential records, or browser profile contents.

Audit storage is outside the principal boundary, owner-only, append-oriented, hash-chained across rotation, and optionally externally checkpointed. A terminal write failure after an irreversible response places agent support in persistent degraded mode until an administrator repairs and acknowledges it. Human UHID operations remain available.

## Administrative and principal interfaces

The daemon exposes separate local interfaces:

- Administrative interface: profile, policy, launch, credential revocation, browser-lease revocation, and audit.
- Principal interface: health, capabilities, instructions, intent or grant request status, cancellation, and non-secret isolated credential metadata.
- UHID endpoints: native CTAP traffic only.

The principal interface can request only policy-permitted delegation and cannot approve it, alter policy, select arbitrary human credentials, extend deadlines, access audit, or invoke signing directly. Human confirmation and PIN entry never occur through the principal interface.

Stable errors include at least:

```text
agent_disabled
profile_not_found
profile_disabled
principal_authentication_failed
principal_session_expired
policy_denied
policy_changed
authorization_required
authorization_conflict
authorization_expired
authorization_consumed
endpoint_unavailable
endpoint_mismatch
rp_id_mismatch
credential_mismatch
operation_not_permitted
user_presence_denied
user_verification_required
credential_revoked
credential_corrupt
browser_lease_expired
browser_cleanup_failed
audit_unavailable
audit_degraded
protocol_version_mismatch
```

Errors return one safe recommended action and never recommend fallback to the human endpoint or weaker verification.

## Failure behavior

| Failure | Required behavior |
|---|---|
| Agent device identity or permissions cannot be proven | Do not launch the browser; destroy the endpoint |
| Human endpoint is visible inside the principal | Abort the principal session |
| Agent endpoint is visible to the human browser identity | Disable the profile and report a security failure |
| Policy or grant changes during a ceremony | Cancel before key use and consume the authorization |
| Delegated credential view mismatches | Return a terminal CTAP error; do not search other credentials |
| Prompt or UV fails | Return a terminal CTAP error without setting UP or UV |
| Audit reservation fails | Do not invoke the credential callback |
| Browser exits or principal disconnects | Revoke the lease, remove the endpoint, and clean the profile |
| Daemon restarts | Recover daemon-owned runtime manifests, terminate verified orphan browser scopes, destroy endpoints, lose in-memory authorizations, and require new authorization |
| Profile cleanup fails | Quarantine the profile path, report degraded cleanup, and never reuse it |
| Agent subsystem fails | Keep the human authenticator available and unchanged |

## Feasibility and release gates

Implementation beyond foundational types is blocked until Phase 0 proves:

1. Multiple uniquely identifiable UHID devices can coexist reliably.
2. Device permissions make the human and agent nodes mutually invisible to the wrong browser identity.
3. A stock browser completes registration and authentication through the intended endpoint without browser changes.
4. A delegated endpoint can use one filtered existing credential while the human endpoint remains functional and credential state stays consistent.
5. Registration, enumeration, deletion, and a second assertion are impossible through the delegated view.
6. The temporary endpoint can drain and disappear after one assertion without corrupting the browser exchange.
7. The launcher can enforce principal, profile, filesystem, socket, and device isolation without a same-user fallback.
8. The trusted prompt produces truthful packet-level UP and UV results.
9. Browser expiry and revocation terminate the process and prevent profile reuse.
10. Existing human behavior and storage remain compatible.

Failure of device isolation, credential filtering, truthful flags, or human-flow compatibility blocks the feature and requires this ADR to be revised.

Before release, an independent review must assess device routing, shared-store synchronization, principal isolation, prompt integrity, policy and authorization races, browser control and cleanup, audit durability, and regression risk. Critical or high findings block release.

## Consequences

### Positive

- Request classification is structural and independent of page claims.
- Browser origin processing remains native and unchanged.
- The user's credential is reused without copying it in delegated mode.
- Isolated credentials remain independently revocable.
- One daemon coordinates human and delegated credential state.
- Temporary authorization is consumed before the browser lease begins.

### Negative

- Multi-endpoint UHID support changes the current single-device daemon model.
- Secure device-node isolation is Linux-specific and deployment-sensitive.
- Delegated mode cannot show an independently authenticated exact origin.
- The browser session may outlive Passless control if session material is copied.
- A managed ephemeral browser and restricted automation boundary increase the trusted computing base.
- Some RPs may not work in a fresh ephemeral profile or may require federated redirects that broaden practical session authority.

## Deferred decisions

Separate decisions are required for:

- Remote principals and non-Unix transports.
- RP-integrated session revocation.
- Durable or transferable delegation grants.
- Multiple assertions under one grant.
- Cross-host browser sessions.
- Mandatory remote or TPM-backed audit checkpoints.
- Autonomous OAuth, workload-identity, or cooperating-RP features.

## Alternatives considered

### Separate daemon process for agent endpoints

Rejected. Running agent endpoints in a separate process would require inter-process credential access, duplicating the storage TCB and creating synchronization hazards for shared human credential state. One daemon with isolated workers preserves single-owner storage and serialized mutation.

### Browser extension or native messaging host for agent WebAuthn

Rejected. Adding a browser extension or native messaging host introduces a browser integration TCB, bypasses the stock browser's origin validation, and requires per-browser maintenance. Stock browser WebAuthn over a dedicated UHID endpoint reuses existing origin enforcement without browser modification.

### Per-request classification on a shared endpoint

Rejected. CTAP requests do not carry caller identity. A shared endpoint cannot distinguish human from agent traffic, making policy enforcement reliant on timing or caller-provided labels that an adversary can race or forge.

### Copy user credentials into agent-isolated storage

Rejected. Copying credentials breaks coordinated signature-counter state, exports high-value key material across trust boundaries, and removes the ability to serialize human and delegated access through one storage owner.

## Rollout

The architecture rolls out through the phased approach in the [implementation plan](../plans/agent-passkey-implementation.md):

1. Phase 0 proves deterministic device identity, mutual endpoint invisibility, and stock browser WebAuthn compatibility.
2. Phases 1-7 build domain types, multi-endpoint runtime, principal launcher, credential isolation, policy, audit, and ceremony services.
3. Phase 8 provides CLI, documentation, and operations tooling.
4. Phase 9 validates the complete boundary through system testing and independent security review.

Agent support remains opt-in and experimental until Phase 9 passes. The human authenticator remains fully operational with agent support compiled but disabled. See the [implementation plan](../plans/agent-passkey-implementation.md) for complete phase gates and exit criteria.

## Rollback

The architecture supports rollback without affecting human credentials or configuration:

1. Disable all agent profiles and revoke active grants, intents, and browser leases.
2. Destroy active agent endpoints and terminate managed ephemeral browsers.
3. Quarantine profiles that fail cleanup.
4. Set `[agents].enabled = false` or stop the daemon.
5. Revoke isolated credentials locally and instruct operators to remove them at each RP.
6. Preserve audit records for investigation.

The human UHID endpoint, human credential store, and human configuration remain untouched. Endpoint workers are independent; agent-worker failure leaves the human worker operational. See [operations: rollback](../agents/operations.md#rollback) for detailed steps.

## References

- W3C Web Authentication Level 3: https://www.w3.org/TR/webauthn-3/
- FIDO Client to Authenticator Protocol 2.2: https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.html
