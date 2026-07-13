# Managed-browser feasibility probe

This directory contains the Phase 0 probe for the managed-browser design in ADR 0002.

The probe uses the real Chrome `webAuthenticationProxy` API. It:

- Attaches the proxy before test navigation.
- Records the exact proxy event keys.
- Derives the current sole top-level document through `tabs` and `webNavigation`.
- Completes a valid ES256 registration and authentication response.
- Verifies the assertion signature, RP ID hash, flags, and client-data origin as a controlled RP.
- Confirms that an attached proxy can return a terminal error without authenticator fallback.
- Cancels a pending request after a top-level navigation.

The software authenticator in `extension/background.js` is test-only. It deliberately sets UP to exercise response verification and must never be reused in production.

Run the probe with:

```bash
bash tools/agent-feasibility/run.sh
```

`run.sh` uses system Chromium and globally installed Playwright. It launches Chromium under Xvfb when no display is available. Temporary browser profiles are created outside the repository and removed after the run.

The probe exits successfully when its executable checks pass, but the architectural gate is **NO-GO**. `webAuthenticationProxy` request events contain no source tab, frame, origin, or document identifier. Querying the current document after receiving an event cannot prove which document originated that request and leaves a TOCTOU that navigation listeners cannot close.

See [evidence.md](evidence.md) and [ADR 0004](../../docs/decisions/0004-reject-webauthn-proxy-origin-binding.md).
