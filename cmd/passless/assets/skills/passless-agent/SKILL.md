---
name: passless-agent
description: Use Passless agent authentication safely through native WebAuthn and human-approved passkey ceremonies.
license: GPL-3.0
compatibility: Requires Linux, Passless agent support, and a configured isolated or delegated-session profile.
metadata:
  project: passless
  repository: https://github.com/pando85/passless
---

# Passless Agent Authentication

Use Passless only through its agent commands and the stock browser session it launches. Passless never exposes private keys, PINs, cookies, tokens, raw assertions, or arbitrary signing.

## Workflow

1. Run `passless agent capabilities` and use only a listed profile and action.
2. Run `passless agent doctor` before the first operation in a new environment.
3. For an isolated profile, create one intent for the exact registration or authentication operation.
4. For a delegated-session profile, request one delegation for the exact RP ID and configured credential reference.
5. Start work through `passless agent run --profile <profile> -- <command...>` when instructed by the capability response.
6. Wait for the human to approve or deny the trusted Passless prompt. Never ask the human to disclose a PIN or approval capability in chat.
7. Treat denial, expiry, cancellation, policy changes, and endpoint teardown as terminal. Create a new request rather than replaying one.
8. Stop using the managed browser when the lease ends. Local lease expiry does not prove that the RP invalidated its server-side session.

## Security Rules

- Never automate, simulate, cache, or claim user presence or user verification.
- Never request another RP ID, credential, profile, or action after an intent or delegation is created.
- Never access `/dev/uhid`, unrelated hidraw nodes, Passless stores, audit files, runtime sockets, or browser-profile files.
- Never copy session material out of the managed browser or claim that Passless provides unattended WebAuthn.
- Prefer RP-supported OAuth, workload identities, service accounts, or scoped application credentials for unattended work.
- If `passless agent` is unavailable or reports an unsupported capability, stop and report the limitation. Do not fall back to browser injection, extensions, WebAuthn proxying, or raw signing.

Use `passless agent instructions` for the installed version's authoritative command and error contract.
