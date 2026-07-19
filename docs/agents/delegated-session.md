# Delegated-session mode

Delegated-session mode permits exact-policy authentication using configured human credentials and,
when explicitly selected, registration into the human store. The RP sees the same account context
as ordinary use by the human.

## Semantics

- The delegated credential is the same user credential. The RP cannot distinguish agent
  use from human use.
- One grant authorizes one passkey login, not all WebAuthn operations during the browser
  lease.
- A later WebAuthn operation requires another grant and fresh ceremony evidence.
- Local browser-lease expiry is not RP-side session revocation.

## Configuration

```toml
[agents.profiles.opencode]
mode = "delegated-session"
principal_user = "passless-opencode"
credential_refs = ["<credential-ref-hex>"]
delegated_registration_storage = "human"
max_grant_ttl = 120
max_session_ttl = 900
browser_command = ["firefox", "--profile", "<daemon-managed>"]
start_url = "https://github.com/dashboard"
browser_user = "passless-browser"
browser_runtime_root = "/var/run/passless-browser"

[[agents.profiles.opencode.rules]]
rp_id = "github.com"
register = { authorization = "confirm", user_presence = "human", user_verification = "human" }
authenticate = { authorization = "allow", user_presence = "policy", user_verification = "policy" }

[agents.profiles.opencode.device]
name = "passless-agent-opencode"
phys = "opencode-phys"
uniq = "opencode-uniq"
vendor_id = 4660
product_id = 22136
```

- `browser_user` must differ from `principal_user`.
- `browser_runtime_root` must be owned by `browser_user` with mode 0700; the principal never sees the filesystem path.
- `credential_refs` are non-secret SHA-256 digests over credential IDs.

## Workflow

1. Operator validates configuration:
   ```bash
   passless agent-admin profile check opencode
   ```
2. Operator launches the principal session:
   ```bash
   passless agent run --profile opencode -- /usr/local/bin/agent-command
   ```

   The `agent run` command requires an absolute executable path owned by root,
   attaches stdio to the principal process, and waits for it to exit. See
   [isolated mode](isolated.md#agent-run-behavior) for details.

3. Inside the session, the principal requests delegation:
   ```bash
   passless agent --profile opencode delegation request \
     --rp github.com --credential <credential-ref-hex> \
     --session-ttl 900 --reason "CI deploy"
   ```
4. The daemon launches an ephemeral browser and evaluates the exact authentication rule.
5. A `confirm` rule presents the trusted prompt; an `allow` rule resolves the one-shot operation
   without a notification. The configured UP/UV sources are recorded in audit.
6. The local browser lease starts at the clamped monotonic deadline.
7. The grant and delegated credential view are consumed after the assertion.

## Local lease vs RP revocation

The local browser lease controls how long Passless keeps the ephemeral browser available.
It does not alter the RP's cookie lifetime or prove that the RP invalidated its server-side
session. If compromise or session copying is suspected, instruct users to revoke RP
sessions through RP controls.

## Browser lease lifecycle

- Starts no earlier than successful CTAP assertion completion.
- Uses a daemon-owned monotonic deadline.
- Terminates on expiry, revocation, browser exit, principal exit, or daemon shutdown.
- The ephemeral profile is removed after browser termination.
- A profile whose cleanup fails is quarantined and never reused.

## Revocation

```bash
passless agent-admin delegation list --profile opencode
passless agent-admin delegation revoke <grant-id> --confirm
passless agent-admin session revoke <session-id> --confirm
```
