# ADR 0005: Delegated Autonomous Authentication via a Daemon-Backed WebAuthn Proxy Extension

- **Status:** Accepted (finding); Proposed (redesign)
- **Date:** 2026-08-02
- **Decision owners:** Passless maintainers
- **Implementation status:** Not started
- **Related decisions:** [ADR 0002](0002-native-webauthn-agent-architecture.md), [ADR 0003](0003-portable-tpm-credential-keys.md), [ADR 0004](0004-external-cdp-endpoint-exposure.md)
- **Amends:** the delegated-autonomous path of ADR 0002, and the interaction-manager / pre-authorization additions on branch `feat/agent-autonomous-auth`

## Context

ADR 0002 defines the agent subsystem so that the daemon is the **only** signer and enforces RP/credential policy, grant TTL, and audit while doing so. The autonomous ("no human in the loop") goal for `delegated-session` was pursued on branch `feat/agent-autonomous-auth` by (a) minting a pre-authorization token on a shared `AgentInteractionManager` at delegation time, (b) auto-approving UP/UV in the human endpoint's callbacks via an `agent_mode` flag, and (c) skipping the agent UHID device so the browser sees a single authenticator.

End-to-end testing against a real relying party (`tea.millaguie.net`) showed that this stack does **not** produce autonomy on its own. Chromium presents a native, non-DOM credential-selection modal for discoverable credentials that no CDP/Playwright call can dismiss, and a UHID authenticator always triggers that modal. The only headless path Chromium offers is the CDP `WebAuthn` virtual-authenticator environment (`WebAuthn.enable` + `addVirtualAuthenticator` + `addCredential`), which **disconnects real discovery and signs inside the browser's automation layer**. The working E2E therefore injected the credential's PKCS#8 private key (extracted from the `pass` vault) into a virtual authenticator.

That working flow has two properties that contradict the ADR 0002 security model:

1. **The key leaves the vault and the daemon is bypassed.** The virtual authenticator signs in the browser process. Daemon logs from successful runs show no `GetAssertion` reaching the worker, the minted interaction token is never consumed, and the RP allowlist / credential refs / grant TTL / audit gate are recorded but never consulted by anything that gates the assertion. The daemon's only load-bearing act was launching Chrome with `--remote-debugging-port`.
2. **A same-user principal can already obtain the key without the daemon.** `spawn_principal` inherits the environment unchanged (`cmd/passless/src/agent/launcher.rs:1119-1174`); `HardenedChildSetup::apply` (`launcher.rs:683-745`) only does `setsid`/`setuid`/rlimits/`PR_SET_NO_NEW_PRIVS` and strips no `GPG_AGENT_INFO`. On a same-user deployment the principal can `pass show fido2/<rp>/<id>` and decrypt the credential directly. The daemon's exclusivity as signer currently rests on OS permission separation in the root-daemon layout, not on code.

For extractable backends (`pass` / software) the ceremony/interaction-manager layer was therefore theatre for the autonomous case. For the **portable TPM** backend the situation is worse, not better: the key is genuinely non-extractable (`cmd/passless/src/storage/tpm/portable/provider.rs:419-451`, signing via `TPM2_Sign` only; no scalar export; see [ADR 0003](0003-portable-tpm-credential-keys.md) and `docs/TPM_PORTABLE.md`), so virtual-authenticator key injection is **impossible** there and the current "autonomous" path does not work for TPM at all. (The legacy non-portable TPM adapter does unseal to RAM, but the agent factory sets its key provider to `None`, so it is not the agent signing path.)

The upstream constraint is structural: stock Chromium on Linux exposes no transport that is simultaneously (i) headless / no security-key modal, (ii) signed by an external daemon, and (iii) key-never-in-browser. UHID/hidraw always shows the modal; the virtual environment is headless but requires the key in-browser; a D-Bus platform authenticator (`libwebauthn` / linux-credentials) shows the portal/fprintd UI. The one Chromium hook that suspends the native modal **and** hands the request to external code is the [`chrome.webAuthenticationProxy`](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy) extension API: an attached extension suspends regular WebAuthn processing (no modal, no UHID discovery), receives `onCreateRequest` / `onGetRequest` events, and supplies the response via `completeGetRequest(requestId, ...)`. It is designed for remote-desktop forwarding but is available to any extension holding the permission (the enterprise policy `WebAuthenticationRemoteDesktopAllowedOrigins` gates only the separate, more dangerous `remoteDesktopClientOverride` origin-override, not basic proxying).

## Decision

Redesign delegated-session autonomy around a **daemon-backed `webAuthenticationProxy` extension** loaded into the daemon-launched browser (`--load-extension`), instead of around an agent UHID endpoint plus ceremony handler plus interaction-manager pre-authorization.

1. The extension calls `chrome.webAuthenticationProxy.attach()`, suspending Chromium's native WebAuthn UI and discovery.
2. On `onGetRequest`, the extension forwards the request (RP ID, challenge, allow-list, requesting origin) to the daemon over a session-authenticated local channel.
3. The daemon checks the active grant, the RP allowlist, the credential refs, and the audit gate (the same machinery that already gates the ceremony handler), then signs via the **existing** `CredentialKeyProvider` for that credential and returns `authenticatorData` + `signature` (+ `userHandle`, `credentialId`). The extension calls `completeGetRequest` with those; the browser assembles the final `PublicKeyCredential`. The private key never leaves the daemon.
4. UP/UV under an `allow` rule are resolved by the daemon's policy check on the sign request (no desktop notification); a `confirm` rule is resolved by the existing human prompt path.

Consequences for the current branch's additions: for **delegated-session autonomy** the agent UHID device, the `AgentCeremonyHandler` wrap, the `AgentInteractionManager` pre-authorization mint, the `agent_mode` callback flag, and the `with_shared_storage_and_pre_authorization` constructor become unnecessary and are slated for removal. They remain **load-bearing for `isolated` mode** (agent-owned credentials, `cmd/passless/src/agent/runtime.rs:1799-1877`, reads gated by ceremony scope at `cmd/passless/src/agent/storage.rs:743-844`) and for `confirm`-policy flows, which are untouched.

The CDP virtual-authenticator key-injection workflow is retained only as a **documented legacy/test path** (see the installed `passless-agent` skill) and must not be presented as the production autonomy mechanism, because it leaks the key into the browser and bypasses policy.

## Consequences

### Positive

- Honest security model: the daemon is again the only signer, and policy / refs / grant TTL / audit genuinely gate every autonomous assertion.
- Works on **portable TPM** by construction, because signing reuses the key provider (`TPM2_Sign`); the extension never sees key material. This is the first path that gives TPM autonomy at all.
- No native credential modal and no desktop notification in the `allow` case.
- Net reduction in moving parts for delegated autonomy (no second UHID device, no per-ceremony token mint/consume race, no UP/UV callback interception).

### Negative

- A new artifact: a packaged browser extension plus its local channel to the daemon, increasing the trusted computing base of a session.
- `clientDataJSON` correctness: the signature is over `authenticatorData || SHA256(clientDataJSON)`, and the daemon's `clientDataJSON` (or `clientDataHash`) must byte-match what the browser assembles. Whether `onGetRequest` delivers the hash/`clientDataJSON` directly or the daemon must reconstruct it canonically is a footgun that can only be caught by a real-RP round-trip.
- The extension↔daemon channel needs a session-scoped authentication design (native messaging vs. localhost bearer token).
- Migration: existing `delegated-session` automation that relied on the (bypassed) ceremony path must move to the extension path.

## Alternatives considered

- **CDP virtual authenticator with injected key (current working E2E).** Rejected as the production mechanism: private key resides in the browser automation layer and policy/audit are not enforced. Kept as a legacy/test path.
- **UHID authenticator + auto-dismiss the modal.** Impossible: the modal is a non-DOM OS/Chromium view, not reachable from CDP; and any UHID device re-triggers it.
- **Linux platform authenticator via D-Bus portal (`libwebauthn`).** Shows the portal / `fprintd` UI and is a large, system-wide integration; does not meet the headless goal.
- **Accept manual approval for autonomy.** Status quo; defeats the purpose.
- **`remoteDesktopClientOverride` origin-override extension.** Rejected: it breaks WebAuthn's origin binding and requires an enterprise policy; the basic `webAuthenticationProxy` attach is sufficient and safer.

## What remains load-bearing vs. not

- Load-bearing, unchanged: `isolated` mode; `confirm`-policy human prompts; the grant / policy / refs / audit machinery; the `CredentialKeyProvider` abstraction (software + portable TPM); browser launch and CDP exposure (still used by the agent to drive the page).
- Load-bearing, repurposed: the grant lifecycle and policy/audit checks now gate the new daemon sign-assertion command instead of a CTAP ceremony.
- Not load-bearing for delegated autonomy (slated for removal): the delegated agent UHID endpoint, the delegated `AgentCeremonyHandler`, the interaction-manager pre-authorization mint, the `agent_mode` callback flag, the `with_shared_storage_and_pre_authorization` constructor.

## Rollout

Implementation is sequenced so that no signing code ships without a real-RP round-trip to validate `clientDataJSON`/`authenticatorData`:

1. **Daemon signing oracle.** Add a principal/admin IPC command (e.g. `delegation sign`) that, given an active grant, RP ID, challenge, and origin, enforces policy/refs/audit and returns `authenticatorData` + `signature` via the existing key provider. Unit-test the crypto (sign with a test key, verify with the public key) and assert `authenticatorData` byte-equality against the soft-fido2 builder for identical inputs. Additive only; nothing deleted.
2. **Minimal proxy extension + browser load.** Package the extension, load it via `--load-extension`, wire `onGetRequest` → daemon sign command → `completeGetRequest`. E2E-verify against `tea.millaguie.net` (this is the first point the `clientDataJSON` contract is validated end-to-end).
3. **Delete the bypassed delegated ceremony stack** listed above, once the extension path is green; keep `isolated` mode and `confirm` flows intact. Update the `passless-agent` skill to make the proxy path authoritative and demote the virtual-authenticator path to legacy/test.
4. **TPM E2E.** Repeat the E2E with a portable-TPM-backed credential to confirm autonomy without key extraction.

## Deferred decisions

- Extension↔daemon channel: native messaging (browser-authenticated by manifest) vs. localhost websocket with a per-session bearer token written into the browser profile directory.
- `clientDataJSON` ownership: prefer the daemon consuming a `clientDataHash`/`clientDataJSON` supplied by the proxy event if Chromium provides it; otherwise the daemon reconstructs it canonically and the E2E in slice 2 is the gate.
- Whether the same proxy extension also handles `onCreateRequest` for delegated registration, or registration stays human-driven.

## References

- [`chrome.webAuthenticationProxy`](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy) extension API.
- W3C WebAuthn, [Remote Desktop Support explainer](https://github.com/w3c/webauthn/blob/main/explainers/remote-desktop-support.md) (origin of the proxy model).
- Chromium commit `9d2480a` (`WebAuthenticationRemoteDesktopAllowedOrigins` policy; scopes the origin-override path, not basic proxying).
- [`linux-credentials/libwebauthn`](https://github.com/linux-credentials/libwebauthn) (D-Bus platform authenticator; rejected, shows UI).
- Chrome DevTools MCP issue on invisible passkey dialogs (motivation for headless autonomy).
- Code: human signing `vendor/soft-fido2-ctap/src/commands/get_assertion.rs:645-651`; software key in RAM `vendor/soft-fido2-ctap/src/key_provider.rs:302-314`; portable TPM sign `cmd/passless/src/storage/tpm/portable/provider.rs:419-451`; principal env inheritance `cmd/passless/src/agent/launcher.rs:1119-1174`; isolated load-bearing path `cmd/passless/src/agent/runtime.rs:1799-1877`; delegated view `cmd/passless/src/agent/storage.rs:241-249`.
