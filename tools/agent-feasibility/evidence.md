# Phase 0 managed-browser feasibility evidence

- **Date:** 2026-07-13
- **Result:** NO-GO
- **Chromium:** 150.0.7871.114
- **API:** `chrome.webAuthenticationProxy`
- **Probe:** `bash tools/agent-feasibility/run.sh`
- **Machine-readable result:** `evidence.json`

## Verified results

The executable probe verifies:

1. Chromium loads the Manifest V3 extension and attaches `webAuthenticationProxy` before test navigation.
2. A create-request event contains exactly `requestId` and `requestDetailsJson`.
3. The extension can separately query one current normal window, tab, top-level frame, origin, and `documentId`.
4. An attached proxy can complete a request with a terminal `NotAllowedError` without invoking another authenticator.
5. A top-level navigation observed after a request is pending can cancel that request.
6. A test-only ES256 authenticator can return valid registration and authentication responses through the proxy.
7. The controlled RP verifies the registration RP hash and flags, assertion RP hash and UP flag, client-data origin and type, and assertion signature.

The probe derives all reported values from the running extension, browser, and RP. It does not hard-code a passed gate result.

## Blocking finding

Chrome's documented and observed proxy event is:

```text
CreateRequest/GetRequest {
    requestId,
    requestDetailsJson
}
```

It has no source tab, frame, origin, or document identifier. `tabs` and `webNavigation` describe browser state at the time the extension queries them; they do not bind that state to the earlier WebAuthn request.

The strict one-window, one-tab, one-frame profile reduces ambiguity but does not remove the time-of-check/time-of-use gap:

1. Document A starts a WebAuthn request.
2. The browser queues the proxy event.
3. A navigation commits to document B before or while the extension queries current browser state.
4. The extension can observe B and cannot prove whether A or B created the request.
5. `onCommitted` cannot reliably repair this because it may run before the request is inserted into the extension's pending map, and the proxy event has no source identifier to correlate with the navigation.

The probe did not reproduce a false binding on the tested Chromium build. That is not a security guarantee, and the API contract provides no ordering or identity property on which production code can rely.

## Gate matrix

| ADR 0002 feasibility item | Result | Evidence |
|---|---|---|
| Launch dedicated Chromium profile | PASS | Playwright persistent temporary profile |
| Trustworthy top-document and exact-origin binding | **FAIL** | Proxy event lacks source identity; TOCTOU remains |
| Authenticated extension/native-host channel | NOT RUN | Work stopped at the blocking origin gate |
| Valid registration and authentication | PASS | Browser accepted responses; RP verified assertion signature |
| Canonical request test vectors | NOT RUN | Phase 1 is blocked |
| No UHID, personal passkey, or profile access | NOT RUN | Phase 1 is blocked |
| Proxy failure gives hard failure without fallback | PASS for explicit proxy rejection | Page received terminal `NotAllowedError` |
| Cancellation and timeout propagation | PARTIAL | Top-level navigation cancellation tested |
| Intent binding and cross-principal isolation | NOT RUN | Requires blocked implementation phases |
| Truthful production UP and UV | NOT RUN | Probe authenticator is explicitly test-only |
| Human/machine credential isolation | NOT RUN | Requires blocked implementation phases |
| Policy change and revocation races | NOT RUN | Requires blocked implementation phases |
| Protected audit pre-write | NOT RUN | Requires blocked implementation phases |
| Principal sandbox isolation | NOT RUN | Requires blocked implementation phases |
| Reproducible browser requirements | PARTIAL | Chromium and probe commands recorded |

## Decision

ADR 0002 requires trusted origin context and says failure to prove it blocks the feature. The requirement is not met. No production protocol, credential storage, audit, launcher, native host, or ceremony engine implementation may proceed from this transport design.

Any replacement must provide a browser-authenticated request envelope that directly binds the WebAuthn request to its source origin and document, or use a different browser integration with equivalent guarantees. It requires a new ADR and a new Phase 0 gate.

## Sources

- Chrome `webAuthenticationProxy`: https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy
- ADR 0002: `docs/decisions/0002-managed-browser-interactive-passkeys.md`
- ADR 0004: `docs/decisions/0004-reject-webauthn-proxy-origin-binding.md`
