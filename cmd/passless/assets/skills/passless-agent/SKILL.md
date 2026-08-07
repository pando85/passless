---
name: passless-agent
description: Use Passless agent authentication safely through native WebAuthn and explicit exact-RP ceremony policy. Includes Playwright MCP integration for high-level browser automation with passkey support.
license: GPL-3.0
compatibility: Requires Linux, Passless agent support, and a configured same-user or isolated profile.
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
6. For a same-user profile, the agent uses the human credential backend directly. No intent creation is needed for authentication — the daemon enforces policy on each WebAuthn call.
7. Follow the matched action policy. A `confirm` rule requires the human to approve or deny the trusted Passless prompt. An `allow` rule resolves the operation without a notification using policy UP/UV. Never ask the human to disclose a PIN or approval capability in chat. Never read PINs or confirmation from stdin.
7b. For fully autonomous browser automation (no native credential selection dialog), the production path is the daemon-backed MAIN-world override described below. The CDP virtual authenticator workflow is legacy/test-only and must not be used for production.
8. Treat denial, expiry, cancellation, policy changes, and endpoint teardown as terminal. Create a new request rather than replaying one.
9. Stop using the managed browser when the lease ends. Local lease expiry does not prove that the RP invalidated its server-side session.

## Local documentation

When a Passless source checkout is available, start with `docs/agents/README.md`. Use
`docs/agents/same-user.md` for same-user mode, `docs/agents/isolated.md` for agent-owned credentials,
`docs/agents/security.md` for authority boundaries, and `docs/agents/operations.md` for audit and revocation.
Search locally with:

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

## Playwright MCP Integration

Passless can be combined with Playwright MCP for high-level browser automation while maintaining passkey authentication. The passless-managed browser exposes CDP on a configurable port, which Playwright can connect to.

### Architecture

```
Playwright MCP (high-level API)
    ↓ connectOverCDP
Chromium with passless extension (CDP port 9222)
    ↓
WebAuthn intercepted → passless daemon signs → authenticated
```

### Configuration

The passless profile must expose CDP on a TCP port:

```toml
[agents.profiles.coding]
browser_cdp_expose = "port"
browser_cdp_port = 9222
```

### Connecting Playwright to Passless Browser

Instead of launching a new browser, connect to the passless-managed one:

```javascript
import { chromium } from 'playwright';

// Connect to passless-managed browser
const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
const contexts = browser.contexts();
const context = contexts[0];
const pages = context.pages();
const page = pages[0] || await context.newPage();

// Use Playwright's high-level API
await page.goto('https://tea.millaguie.net/user/login');
await page.click('.signin-passkey');
// WebAuthn is handled by passless extension automatically
```

### Helper Script for Agent Sessions

When using passless with Playwright MCP, follow this pattern:

1. **Check if browser is running:**
   ```bash
   passless agent run --profile <profile> -- /usr/bin/bash -c '
     passless agent --profile <profile> browser-status
   '
   ```

2. **Launch browser if not running:**
   ```bash
   passless agent-admin browser launch --profile <profile>
   ```

3. **Get CDP endpoint:**
   The CDP endpoint is `http://127.0.0.1:<browser_cdp_port>` (default: 9222)

4. **Connect Playwright and automate:**
   Use the Playwright MCP tools or direct Playwright API to control the browser.

### Benefits of Playwright Integration

| Feature | Raw CDP (websocat) | Playwright MCP |
|---------|-------------------|----------------|
| Navigation | Manual JSON-RPC | `page.goto()` |
| Clicking | Manual DOM queries | `page.click()` |
| Auto-wait | Manual polling | Built-in |
| Selectors | CSS/XPath only | Text, role, testid |
| Screenshots | Manual CDP calls | `page.screenshot()` |
| WebAuthn | Passless extension | Passless extension |

### Security Model Preserved

When using Playwright MCP with passless:
- The passless extension still intercepts all WebAuthn calls
- The daemon still enforces RP policy, credential refs, TTL, and audit
- Private keys never leave the daemon
- Playwright only controls navigation and DOM interaction, not authentication

### Example: Login to Gitea with Passkey

```bash
# 1. Launch passless browser
passless agent-admin browser launch --profile coding

# 2. Use Playwright MCP to connect and automate
# (In opencode with Playwright MCP configured)
```

```javascript
// Connect to passless browser
const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
const page = browser.contexts()[0].pages()[0];

// Navigate and login
await page.goto('https://tea.millaguie.net/user/login');
await page.click('.signin-passkey');
// Passless extension handles WebAuthn, page is now authenticated

// Verify login
await page.waitForURL('**/');
console.log(await page.title()); // "Dashboard - ..."
```

## Daemon-backed WebAuthn override (production path)

The safe production path for fully autonomous authentication is an MV3 extension loaded into the daemon-launched browser. A MAIN-world `document_start` content script overrides `navigator.credentials.get`, reads each frame's `location.origin`, and forwards the request plus origin to the passless daemon. The daemon enforces origin matching, RP policy, credential refs, grant TTL, and audit, then signs via the `CredentialKeyProvider` (software or portable TPM) and returns `authenticatorData` + `signature`. The content script assembles a duck-typed `PublicKeyCredential`-like result and resolves the promise. The private key never leaves the daemon.

This path works with non-extractable TPM keys because the daemon performs `TPM2_Sign` directly; no key material is injected into the browser.

Implementation status: implemented and verified against a real relying party on 2026-08-03. The daemon signing oracle, the MAIN-world override extension, HTTP integration/security/audit/counter tests, cancellation cleanup regression tests, and portable-TPM unit suites are complete (see [ADR 0005](../../../../docs/decisions/0005-delegated-autonomous-authentication-redesign.md) and the [verification matrix](../../../../docs/plans/adr-0005-verification-matrix.md)). The full TPM E2E with a real credential is the remaining rollout slice; the bypassed delegated pre-authorization path has been removed.

## Passkey Registration

Agents can register passkeys without human interaction using the daemon-backed extension.

### Configuration

Enable registration in your agent profile:

```toml
[[profiles.ci-agent.rules]]
rp_id = "gitea.example.com"
register = { authorization = "allow", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "none", user_verification = "none" }
```

### Registration Flow

1. Request a registration grant via IPC:
   ```rust
   AdminRequest::RequestRegistration {
       profile_id: "ci-agent".into(),
       rp_id: "gitea.example.com".into(),
       max_session_ttl: 300,
       reason: Some("CI/CD setup".into()),
   }
   ```

2. Navigate to the RP's registration page in the agent-launched browser

3. The extension intercepts `navigator.credentials.create()` and forwards to the daemon's `/register` endpoint

4. The daemon:
   - Validates the registration grant
   - Checks policy (register.authorization == Allow)
   - Generates a new keypair via CredentialKeyProvider
   - Constructs authenticatorData with attested credential data
   - Writes the credential to storage
   - Returns the attestation object

5. The extension returns a duck-typed PublicKeyCredential to the RP

6. The credential is now available for authentication

### Security Model

- Registration is **denied by default** - requires explicit per-RP opt-in
- The daemon enforces origin, policy, and grant validation
- Private keys never leave the daemon (even during generation)
- All registration operations are audited
- Works with both software and TPM backends

### Examples

See the [Agent Registration Guide](../../../../docs/AGENT_REGISTRATION.md) for detailed examples.

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
