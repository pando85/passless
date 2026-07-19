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

## Security Rules

- Never claim that policy UP/UV represents human interaction or local human verification.
- Never request another RP ID, credential, profile, or action after an intent or delegation is created.
- Never access `/dev/uhid`, unrelated hidraw nodes, Passless stores, audit files, runtime sockets, or browser-profile files.
- Never copy session material out of the managed browser. Use unattended WebAuthn only when the exact action capability reports an operator-owned `allow` rule with policy evidence.
- Never pass PINs through stdin, environment, or chat.
- Prefer RP-supported OAuth, workload identities, service accounts, or scoped application credentials for unattended work.
- If `passless agent` is unavailable or reports an unsupported capability, stop and report the limitation. Do not fall back to browser injection, extensions, WebAuthn proxying, or raw signing.

Use `passless agent --profile <profile> instructions` for the installed version's authoritative command and error contract.
