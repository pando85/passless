---
name: passless-agent
description: Use Passless agent authentication safely through native WebAuthn and explicit exact-RP ceremony policy.
license: GPL-3.0
compatibility: Requires Linux, Passless agent support, and a configured isolated or delegated-session profile.
metadata:
  project: passless
  repository: https://github.com/pando85/passless
---

# Passless Agent Authentication

Use Passless only through its agent commands and the stock browser session it launches. Passless never exposes private keys, PINs, cookies, tokens, raw assertions, or arbitrary signing.

## Workflow

1. Operator validates the profile before launch:
   ```
   passless agent-admin profile check <profile>
   ```
2. Operator launches the principal session:
   ```
   passless agent run --profile <profile> -- <command...>
   ```
   Principal commands happen inside the launched command. The operator does not run them separately.
3. Inside the session, run `passless agent --profile <profile> doctor` before the first operation.
4. Run `passless agent --profile <profile> capabilities` and use only a listed profile and action.
5. For an isolated profile, create one intent for the exact operation:
   ```
   passless agent --profile <profile> intent create register --rp <rp-id> --reason "<reason>"
   passless agent --profile <profile> intent create authenticate --rp <rp-id> --credential <credential-ref-hex> --reason "<reason>"
   ```
6. For a delegated-session profile, request one delegation for the exact RP ID and credential reference:
   ```
   passless agent --profile <profile> delegation request --rp <rp-id> --credential <credential-ref-hex> --session-ttl <seconds> --reason "<reason>"
   ```
7. Follow the matched action policy. A `confirm` rule requires the human to approve or deny the trusted Passless prompt. An `allow` rule resolves the operation without a notification using policy UP/UV. Never ask the human to disclose a PIN or approval capability in chat. Never read PINs or confirmation from stdin.
7b. For fully autonomous browser automation (no native credential selection dialog), the production path is the daemon-backed MAIN-world override described below. The CDP virtual authenticator workflow is legacy/test-only and must not be used for production.
8. Treat denial, expiry, cancellation, policy changes, and endpoint teardown as terminal. Create a new request rather than replaying one.
9. Stop using the managed browser when the lease ends. Local lease expiry does not prove that the RP invalidated its server-side session.

## Local documentation

When a Passless source checkout is available, start with `docs/agents/README.md`. Use
`docs/agents/isolated.md` for agent-owned credentials, `docs/agents/delegated-session.md` for human
credential delegation, `docs/agents/security.md` for authority boundaries, and
`docs/agents/operations.md` for audit and revocation. Search locally with:

```
rg --files docs/agents docs/decisions docs/plans
rg -n "<topic>" docs/agents docs/decisions docs/plans
```

## Browser-control examples

The `browser-control` command sends CDP requests to the managed browser. CDP is the full-session authority interface. Output may contain cookies, DOM, and network data.

```
passless agent --profile <profile> browser-control --request '{"id":1,"method":"Page.navigate","params":{"url":"https://<rp-host>/path"}}'
```

Or from a file (owner, symlink, and size checked):
```
passless agent --profile <profile> browser-control --request-file /path/to/cdp-request.json
```

- Do not mix CDP output with credential or admin output.
- Do not log, cache, or forward CDP responses.
- The principal holds full RP browser-session authority during the lease.

## Daemon-backed WebAuthn override (production path)

The safe production path for fully autonomous authentication is an MV3 extension loaded into the daemon-launched browser. A MAIN-world `document_start` content script overrides `navigator.credentials.get`, reads each frame's `location.origin`, and forwards the request plus origin to the passless daemon. The daemon enforces origin matching, RP policy, credential refs, grant TTL, and audit, then signs via the `CredentialKeyProvider` (software or portable TPM) and returns `authenticatorData` + `signature`. The content script assembles a duck-typed `PublicKeyCredential`-like result and resolves the promise. The private key never leaves the daemon.

This path works with non-extractable TPM keys because the daemon performs `TPM2_Sign` directly; no key material is injected into the browser.

Implementation status: not yet complete. The daemon signing oracle and the MAIN-world override extension are planned (see [ADR 0005](../../../../docs/decisions/0005-delegated-autonomous-authentication-redesign.md)). Do not rely on this path until the rollout slices are green.

## Legacy/test-only: CDP virtual authenticator

**This workflow is legacy and test-only. It is not the production autonomy mechanism.** It extracts the raw private key from the pass vault and injects it into Chromium's virtual authenticator, bypassing the daemon's policy and audit gates. It cannot support non-extractable TPM keys. Use it only for development and testing in trusted environments. The production path is the daemon-backed MAIN-world override described above.

Chromium shows a native credential selection dialog for discoverable credentials that blocks automation. The CDP WebAuthn domain with a virtual authenticator injected with the real credential's private key can bypass this for testing.

### Prerequisites

- The delegation request must use an `allow` authorization rule with policy UP/UV.
- The credential's private key must be extractable from the pass vault (EC2/P-256 COSE key format).
- Playwright or any CDP client with `WebAuthn` domain support.

### Credential extraction

Extract the EC2 private scalar from the pass vault CBOR credential and convert to PKCS#8 DER:

```python
import subprocess, cbor2, base64, json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

cred_path = "fido2/<rp-id>/<credential-id-hex>"
raw = subprocess.run(["pass", "show", cred_path], capture_output=True).stdout
cred = cbor2.loads(raw)
d_int = int.from_bytes(bytes(cred["private_key"]), "big")
pk = ec.derive_private_key(d_int, ec.SECP256R1(), default_backend())
pkcs8 = pk.private_bytes(serialization.Encoding.DER,
    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
print(json.dumps({
    "credentialId": base64.b64encode(bytes(cred["id"])).decode(),
    "privateKey": base64.b64encode(pkcs8).decode(),
    "rpId": cred["rp"]["id"],
    "userHandle": base64.b64encode(bytes(cred["user"]["id"])).decode(),
}))
```

### CDP virtual authenticator workflow

Connect to the managed browser's CDP endpoint and inject the credential:

```javascript
const cdp = await page.context().newCDPSession(page);
await cdp.send('WebAuthn.enable', { enableUI: false });
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: {
    protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb',
    hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true,
  },
});
await cdp.send('WebAuthn.addCredential', {
  authenticatorId,
  credential: {
    credentialId: CRED.credentialId,
    isResidentCredential: true,
    rpId: CRED.rpId,
    privateKey: CRED.privateKey,
    userHandle: CRED.userHandle,
    signCount: Math.floor(Date.now() / 1000),
  },
});
```

### Sign count management

The server tracks sign counts and rejects replayed assertions. Use a monotonically increasing value (e.g. `Math.floor(Date.now() / 1000)`) for each virtual authenticator session to prevent replay rejection.

### Trust boundary note

The virtual authenticator approach extracts the raw private key from the pass vault and injects it into Chromium's virtual authenticator environment. This bypasses the passless daemon entirely: policy, grant TTL, audit, and origin checks are not enforced. The key material exists in the CDP client's memory during the session. This path cannot work with non-extractable TPM keys. Use only for development and testing in trusted, operator-controlled environments.

## Security Rules

- Never claim that policy UP/UV represents human interaction or local human verification.
- Never request another RP ID, credential, profile, or action after an intent or delegation is created.
- Never access `/dev/uhid`, unrelated hidraw nodes, Passless stores, audit files, runtime sockets, or browser-profile files.
- Never copy session material out of the managed browser. Use unattended WebAuthn only when the exact action capability reports an operator-owned `allow` rule with policy evidence.
- CDP virtual authenticators are legacy/test-only. The raw private key exists in the CDP client process memory, the daemon is bypassed, and non-extractable TPM keys are unsupported. Use only in trusted, operator-controlled test environments.
- Never pass PINs through stdin, environment, or chat.
- Prefer RP-supported OAuth, workload identities, service accounts, or scoped application credentials for unattended work.
- If `passless agent` is unavailable or reports an unsupported capability, stop and report the limitation. Do not fall back to browser injection, extensions, WebAuthn proxying, or raw signing.

Use `passless agent --profile <profile> instructions` for the installed version's authoritative command and error contract.
