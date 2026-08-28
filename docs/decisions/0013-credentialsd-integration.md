# ADR 0013: credentialsd integration — validate HID first, defer native provider

- **Status:** Proposed
- **Date:** 2026-08-28
- **Decision owners:** Passless maintainers
- **Related:** issue #462, issue #310, [CLIENT_COMPATIBILITY.md](../CLIENT_COMPATIBILITY.md)

## Context

Passless currently exposes its normal Linux authenticator through UHID:

```text
browser / application
    -> FIDO HID / hidraw
    -> Passless CTAP authenticator
    -> Passless credential backend / key provider
```

This has the useful property that Passless behaves like an ordinary external FIDO2
authenticator, but client confinement and browser/application WebAuthn support can make
the virtual hidraw device difficult or impossible to consume directly.

The Credentials for Linux project (`linux-credentials/credentialsd`) is building a
Linux Credential Manager API around an xdg-desktop-portal gateway, a credential service,
and a separately privileged UI/controller boundary. Its long-term goals include a
uniform interface for third-party credential providers and possibly a Linux platform
authenticator.

This ADR records what is actionable for Passless against the upstream state observed on
2026-08-28 rather than designing against the project's long-term goals.

## Upstream state reviewed

The investigation was performed against `credentialsd` 0.3.0, released 2026-08-27.
That release is an important architectural milestone:

- `credentialsd` now depends on a patched `xdg-desktop-portal` and exposes a portal
  handler rather than the previous FlowControl service;
- `origin` is required for create/get requests and `top_origin` is accepted;
- related-origin requests are validated;
- the browser-extension path has continued to mature;
- current credential transports include USB, NFC and hybrid.

Relevant upstream documents/code:

- `linux-credentials/credentialsd/CHANGELOG.md`
- `linux-credentials/credentialsd/ARCHITECTURE.md`
- `linux-credentials/credentialsd/GOALS.md`
- `linux-credentials/credentialsd/doc/api.md`
- `linux-credentials/credentialsd/credentialsd/src/credential_service/usb.rs`

### Third-party provider API is not implemented yet

Third-party credential providers are explicitly an upstream **goal**, but the current
credential service does not expose a stable provider implementation boundary that
Passless can implement. The concrete handlers in 0.3.0 are USB, NFC and hybrid.

Therefore a "native Passless credentialsd provider" today would require Passless to
invent or depend on an unstabilized upstream interface. That would create maintenance
cost and a second integration boundary before the Linux credential-provider contract is
ready.

### Passless already fits the USB/FIDO handler model

The current credentialsd USB handler enumerates normal HID authenticators through
`libwebauthn`, opens a FIDO HID channel, and performs the regular WebAuthn/CTAP flow.
Passless's UHID endpoint is deliberately designed to appear as an ordinary FIDO2 HID
authenticator, so this is the lowest-complexity integration path:

```text
browser / application
    -> xdg-desktop-portal / credentialsd
    -> credentialsd USB handler
    -> Passless virtual FIDO HID authenticator
    -> existing Passless CTAP + storage/key-provider pipeline
```

This path is expected to preserve Passless's current cryptographic boundary because
credentialsd sees only a normal authenticator. It does not gain access to Passless
private keys, TPM handles, backend storage, or arbitrary signing APIs.

That compatibility is an architectural expectation, not yet a Passless-tested support
claim. It needs an end-to-end interoperability test before documentation says it works.

## Decision

### 1. Do not implement a native credentialsd provider yet

Passless will not create a private provider protocol or track an unstable internal
credentialsd interface merely to remove UHID.

Revisit this decision when upstream has a documented third-party provider API with:

- versioned compatibility expectations;
- clear provider discovery/lifecycle semantics;
- create/get WebAuthn request and response mapping;
- user-presence/user-verification interaction semantics;
- provider cancellation and timeout behavior;
- caller/origin/RP trust semantics;
- a process/permission model suitable for third-party password/passkey managers.

At that point a Passless provider can be evaluated as an adapter into the **same**
credential backend/key-provider pipeline rather than a second authenticator
implementation.

### 2. Validate the existing HID path first

The near-term credentialsd work is an interoperability test, not a new transport in
Passless.

Test at minimum:

```text
credentialsd 0.3.x + supported portal fork
    -> browser integration
    -> USB authenticator discovery
    -> Passless UHID endpoint
    -> makeCredential
    -> getAssertion
```

The matrix should cover:

- discoverable credential registration and username-less authentication;
- PIN/UV-required ceremonies;
- account selection where multiple credentials exist;
- `credProtect` behavior used by Passless;
- cancellation/timeouts;
- one confined client path if the current portal/browser integration supports it;
- comparison with a physical FIDO2 key on the same credentialsd setup.

If Passless is not discovered or a CTAP flow differs from a physical authenticator, fix
that as an interoperability issue rather than bypassing the FIDO boundary with a custom
provider.

### 3. Treat credentialsd as a human-client transport for now

The current Passless agent path relies on browser-derived execution context and daemon
revalidation of exact RP/origin, session capability, operation intent, credential scope,
policy generation, replay state and audit state.

The current credentialsd architecture is not a replacement for that boundary:

- its portal/gateway path is designed around normal client credential requests and user
  interaction;
- upstream still documents **application identity** and stronger **origin binding** as
  future work;
- the reference UI is expected to mediate PIN/touch/credential-selection interactions;
- autonomous Passless UP/UV semantics and isolated credential namespaces are not part of
  the current provider contract.

Therefore agent mode keeps its managed-browser/native-messaging/sign-proxy architecture.
Do not route agent ceremonies through credentialsd merely to unify transports.

This decision can be revisited if credentialsd later provides a trusted client/origin
binding that is at least as strong as the browser-derived context Passless currently
revalidates.

### 4. Keep UHID as the compatibility baseline

A future native provider should be optional and coexist with UHID until it demonstrates
at least equivalent real-world coverage. Passless must retain a standards-level CTAP
path for non-portal clients and tools.

## Security consequences

### HID path

Security-sensitive Passless logic remains behind the existing CTAP boundary:

```text
credentialsd/libwebauthn
    -> CTAP2
    -> Passless
    -> credential backend/key provider
```

This is attractive because credentialsd does not become a Passless key custodian.

The new trust introduced is on the **WebAuthn client side**: credentialsd/portal is
responsible for its own caller, origin/RP and UI mediation before it talks to the FIDO
authenticator. Passless still sees CTAP semantics, not the original browser frame
identity.

### Native provider, if implemented later

A native provider would move the integration boundary above CTAP and therefore requires
a fresh threat-model review. In particular, Passless must not accept page-controlled RP
or origin claims without a trustworthy caller context, and credentialsd must never
receive raw Passless private-key material.

## Validation deliverables for #462

- [ ] Build a reproducible credentialsd 0.3.x test environment.
- [ ] Confirm whether Passless is enumerated by the USB handler as a normal FIDO HID
      authenticator.
- [ ] Run registration + assertion against the same RP with Passless and a physical key.
- [ ] Test discoverable credentials and required UV/PIN flows.
- [ ] Record confined-client behavior through the current portal/browser integration.
- [ ] Document any Passless-specific interoperability failures separately.
- [ ] Re-check upstream for a third-party provider API before each implementation cycle.

## Revisit triggers

Re-evaluate a native provider when one of these occurs:

1. credentialsd publishes a supported third-party provider API;
2. Firefox or Chromium ships the credentialsd/portal path broadly enough that it is a
   meaningful Linux compatibility baseline;
3. UHID/hidraw confinement becomes the dominant Passless support problem;
4. credentialsd gains caller/application identity and origin binding strong enough to
   reconsider agent integration.

## Consequences

- No new Passless credential-provider code is justified today.
- #462 should focus next on real HID interoperability testing.
- `docs/CLIENT_COMPATIBILITY.md` should continue describing credentialsd as emerging and
  explicit-integration dependent until those tests and upstream browser integration are
  mature.
- Agent mode remains architecturally independent from credentialsd for now.
