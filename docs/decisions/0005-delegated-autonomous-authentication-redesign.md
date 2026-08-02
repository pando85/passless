# ADR 0005: Delegated Autonomous Authentication via a Daemon-Backed WebAuthn Extension

- **Status:** Accepted (finding); In progress (redesign)
- **Date:** 2026-08-02
- **Decision owners:** Passless maintainers
- **Implementation status:** Phases 1 and 2 in progress; completion is governed by the [implementation plan](../plans/delegated-autonomy-daemon-proxy-implementation.md)
- **Related decisions:** [ADR 0002](0002-native-webauthn-agent-architecture.md), [ADR 0003](0003-portable-tpm-credential-keys.md), [ADR 0004](0004-external-cdp-endpoint-exposure.md)
- **Amends:** the delegated-autonomous path of ADR 0002, and the interaction-manager / pre-authorization additions on branch `feat/agent-autonomous-auth`

## Context

ADR 0002 defines the agent subsystem so that the daemon is the **only** signer and enforces RP/credential policy, grant TTL, and audit while doing so. The autonomous ("no human in the loop") goal for `delegated-session` was pursued on branch `feat/agent-autonomous-auth` by (a) minting a pre-authorization token on a shared `AgentInteractionManager` at delegation time, (b) auto-approving UP/UV in the human endpoint's callbacks via an `agent_mode` flag, and (c) skipping the agent UHID device so the browser sees a single authenticator.

End-to-end testing against a real relying party (`tea.millaguie.net`) showed that this stack does **not** produce autonomy on its own. Chromium presents a native, non-DOM credential-selection modal for discoverable credentials that no CDP/Playwright call can dismiss, and a UHID authenticator always triggers that modal. The only headless path Chromium offers is the CDP `WebAuthn` virtual-authenticator environment (`WebAuthn.enable` + `addVirtualAuthenticator` + `addCredential`), which **disconnects real discovery and signs inside the browser's automation layer**. The working E2E therefore injected the credential's PKCS#8 private key (extracted from the `pass` vault) into a virtual authenticator.

That working flow has two properties that contradict the ADR 0002 security model:

1. **The key leaves the vault and the daemon is bypassed.** The virtual authenticator signs in the browser process. Daemon logs from successful runs show no `GetAssertion` reaching the worker, the minted interaction token is never consumed, and the RP allowlist / credential refs / grant TTL / audit gate are recorded but never consulted by anything that gates the assertion. The daemon's only load-bearing act was launching Chrome with `--remote-debugging-port`.
2. **A same-user principal can already obtain the key without the daemon.** `spawn_principal` inherits the environment unchanged (`cmd/passless/src/agent/launcher.rs:1119-1174`); `HardenedChildSetup::apply` (`launcher.rs:683-745`) only does `setsid`/`setuid`/rlimits/`PR_SET_NO_NEW_PRIVS` and strips no `GPG_AGENT_INFO`. On a same-user deployment the principal can `pass show fido2/<rp>/<id>` and decrypt the credential directly. The daemon's exclusivity as signer currently rests on OS permission separation in the root-daemon layout, not on code.

For extractable backends (`pass` / software) the ceremony/interaction-manager layer was therefore theatre for the autonomous case. For the **portable TPM** backend the situation is worse, not better: the key is genuinely non-extractable (`cmd/passless/src/storage/tpm/portable/provider.rs:419-451`, signing via `TPM2_Sign` only; no scalar export; see [ADR 0003](0003-portable-tpm-credential-keys.md) and `docs/TPM_PORTABLE.md`), so virtual-authenticator key injection is **impossible** there and the current "autonomous" path does not work for TPM at all. (The legacy non-portable TPM adapter does unseal to RAM, but the agent factory sets its key provider to `None`, so it is not the agent signing path.)

The upstream constraint is structural: stock Chromium on Linux exposes no transport that is simultaneously (i) headless / no security-key modal, (ii) signed by an external daemon, and (iii) key-never-in-browser. UHID/hidraw always shows the modal; the virtual environment is headless but requires the key in-browser; a D-Bus platform authenticator (`libwebauthn` / linux-credentials) shows the portal/fprintd UI. The [`chrome.webAuthenticationProxy`](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy) extension API was the initial candidate: it suspends the native modal and hands the request to external code via `onGetRequest` / `completeGetRequest`. However, `requestDetailsJson` does not carry the calling frame's origin, which the daemon needs to construct a truthful `clientDataJSON` (the signature covers `authenticatorData || SHA-256(clientDataJSON)` and a wrong origin invalidates the assertion). An MV3 extension content script running in the MAIN world at `document_start` can override `navigator.credentials.get` directly and read `window.location.origin` from each frame, which solves the origin problem. The target relying parties (Gitea / Forgejo) perform field access on the returned credential object and therefore accept a duck-typed `PublicKeyCredential`-like result without requiring native `instanceof` identity.

## Decision

Redesign delegated-session autonomy around a **daemon-backed MV3 extension with a MAIN-world `document_start` override of `navigator.credentials.get`**, loaded into the daemon-launched browser (`--load-extension`), instead of around an agent UHID endpoint plus ceremony handler plus interaction-manager pre-authorization.

1. The extension injects a content script into the MAIN world at `document_start` that replaces `navigator.credentials.get` with a wrapper. The wrapper reads `window.location.origin` from the calling frame, serializes the `PublicKeyCredentialRequestOptions`, and forwards both to the daemon over a per-session localhost bearer channel.
2. The daemon checks the active grant, the RP allowlist, the credential refs, and the audit gate (the same machinery that already gates the ceremony handler), constructs a canonical `clientDataJSON` using the frame origin, then signs via the **existing** `CredentialKeyProvider` for that credential and returns `authenticatorData` + `signature` (+ `userHandle`, `credentialId`). The private key never leaves the daemon.
3. The content script assembles a duck-typed `PublicKeyCredential`-like result (with `rawId`, `response.authenticatorData`, `response.signature`, `response.clientDataJSON`, `type: "public-key"`) and resolves the overridden `get()` promise with it. The target Gitea / Forgejo client uses field access and accepts this shape without requiring native `instanceof PublicKeyCredential`.
4. UP/UV under an `allow` rule are resolved by the daemon's policy check on the sign request (no desktop notification). The autonomous endpoint rejects `confirm`; explicit human confirmation remains on the existing ceremony path.
5. `chrome.webAuthenticationProxy` is retained as a **possible fallback** for relying parties that require native `instanceof PublicKeyCredential` behavior, but is not the primary design.

Consequences for the current branch's additions: for **delegated-session autonomy** the agent UHID device, the `AgentCeremonyHandler` wrap, the `AgentInteractionManager` pre-authorization mint, the `agent_mode` callback flag, and the `with_shared_storage_and_pre_authorization` constructor become unnecessary and are slated for removal. They remain **load-bearing for `isolated` mode** (agent-owned credentials, `cmd/passless/src/agent/runtime.rs:1799-1877`, reads gated by ceremony scope at `cmd/passless/src/agent/storage.rs:743-844`) and for `confirm`-policy flows, which are untouched.

The CDP virtual-authenticator key-injection workflow is retained only as a **documented legacy/test-only path** (see the installed `passless-agent` skill) and must not be presented as the production autonomy mechanism, because it leaks the key into the browser, bypasses policy, and cannot support non-extractable TPM keys.

## Consequences

### Positive

- Honest security model: the daemon is again the only signer, and origin / policy / refs / grant TTL / audit genuinely gate every autonomous assertion.
- Works on **portable TPM** by construction, because signing reuses the key provider (`TPM2_Sign`); the extension never sees key material. This is the first path that gives TPM autonomy at all. CDP virtual-authenticator key injection cannot support non-extractable TPM keys.
- No native credential modal and no desktop notification in the `allow` case.
- Net reduction in moving parts for delegated autonomy (no second UHID device, no per-ceremony token mint/consume race, no UP/UV callback interception).
- `clientDataJSON` correctness is resolved by construction: the MAIN-world override reads each frame's `location.origin` directly, so the daemon always has the truthful origin.

### Negative

- A new artifact: a packaged browser extension plus its local channel to the daemon, increasing the trusted computing base of a session.
- Duck-typed credentials: relying parties that perform `instanceof PublicKeyCredential` checks will reject the override result. The `webAuthenticationProxy` fallback exists for this case but adds complexity.
- The per-session localhost bearer token is defense-in-depth; the load-bearing gates are origin matching, RP policy, credential refs, and grant TTL enforced by the daemon.
- Migration: existing `delegated-session` automation that relied on the (bypassed) ceremony path must move to the extension path.

## Alternatives considered

- **CDP virtual authenticator with injected key (current working E2E).** Rejected as the production mechanism: private key resides in the browser automation layer, policy/audit are not enforced, and non-extractable TPM keys cannot be injected. Kept as a legacy/test-only path.
- **`chrome.webAuthenticationProxy` extension (initial candidate).** Rejected as the primary transport: `requestDetailsJson` lacks the calling frame's origin needed to construct truthful `clientDataJSON`. Retained as a possible fallback for relying parties that require native `instanceof PublicKeyCredential` behavior.
- **UHID authenticator + auto-dismiss the modal.** Impossible: the modal is a non-DOM OS/Chromium view, not reachable from CDP; and any UHID device re-triggers it.
- **Linux platform authenticator via D-Bus portal (`libwebauthn`).** Shows the portal / `fprintd` UI and is a large, system-wide integration; does not meet the headless goal.
- **Accept manual approval for autonomy.** Status quo; defeats the purpose.
- **`remoteDesktopClientOverride` origin-override extension.** Rejected: it breaks WebAuthn's origin binding and requires an enterprise policy.

## What remains load-bearing vs. not

- Load-bearing, unchanged: `isolated` mode; `confirm`-policy human prompts; the grant / policy / refs / audit machinery; the `CredentialKeyProvider` abstraction (software + portable TPM); browser launch and CDP exposure (still used by the agent to drive the page).
- Load-bearing, repurposed: the grant lifecycle and policy/audit checks now gate the new daemon sign-assertion command instead of a CTAP ceremony.
- Not load-bearing for delegated autonomy (slated for removal): the delegated agent UHID endpoint, the delegated `AgentCeremonyHandler`, the interaction-manager pre-authorization mint, the `agent_mode` callback flag, the `with_shared_storage_and_pre_authorization` constructor.

## Rollout

Implementation is sequenced so that no signing code ships without a real-RP round-trip to validate `clientDataJSON`/`authenticatorData`:

1. **Daemon signing oracle.** Add a principal/admin IPC command (e.g. `delegation sign`) that, given an active grant, RP ID, challenge, and origin, enforces policy/refs/audit and returns `authenticatorData` + `signature` via the existing key provider. Unit-test the crypto (sign with a test key, verify with the public key) and assert `authenticatorData` byte-equality against the soft-fido2 builder for identical inputs. Additive only; nothing deleted.
2. **MAIN-world override extension + browser load.** Package the MV3 extension with a MAIN-world `document_start` content script that overrides `navigator.credentials.get`, load it via `--load-extension`, wire the override to the daemon sign command returning a duck-typed `PublicKeyCredential` result. The per-session localhost bearer token authenticates the channel; origin/policy/grant checks in the daemon are load-bearing. E2E-verify against `tea.millaguie.net` (this is the first point the `clientDataJSON` contract is validated end-to-end).
3. **Delete the bypassed delegated ceremony stack** listed above, once the extension path is green; keep `isolated` mode and `confirm` flows intact. Update the `passless-agent` skill to make the daemon-backed override path authoritative and demote the CDP virtual-authenticator path to legacy/test-only.
4. **TPM E2E.** Repeat the E2E with a portable-TPM-backed credential to confirm autonomy without key extraction. CDP virtual-authenticator injection cannot support this case.

## Deferred decisions

- Extension-daemon channel: per-session localhost bearer token written into the browser profile directory (defense-in-depth; the load-bearing gates are daemon-side origin/policy/grant checks). Native messaging remains an option.
- Whether the same extension also handles credential creation (`navigator.credentials.create`) for delegated registration, or registration stays human-driven.
- Activation threshold for the `webAuthenticationProxy` fallback: define which relying parties require native `instanceof` and ship the proxy path only for those.

## References

- [`chrome.webAuthenticationProxy`](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy) extension API.
- W3C WebAuthn, [Remote Desktop Support explainer](https://github.com/w3c/webauthn/blob/main/explainers/remote-desktop-support.md) (origin of the proxy model).
- Chromium commit `9d2480a` (`WebAuthenticationRemoteDesktopAllowedOrigins` policy; scopes the origin-override path, not basic proxying).
- [`linux-credentials/libwebauthn`](https://github.com/linux-credentials/libwebauthn) (D-Bus platform authenticator; rejected, shows UI).
- Chrome DevTools MCP issue on invisible passkey dialogs (motivation for headless autonomy).
- Code: human signing `vendor/soft-fido2-ctap/src/commands/get_assertion.rs:645-651`; software key in RAM `vendor/soft-fido2-ctap/src/key_provider.rs:302-314`; portable TPM sign `cmd/passless/src/storage/tpm/portable/provider.rs:419-451`; principal env inheritance `cmd/passless/src/agent/launcher.rs:1119-1174`; isolated load-bearing path `cmd/passless/src/agent/runtime.rs:1799-1877`; delegated view `cmd/passless/src/agent/storage.rs:241-249`.
