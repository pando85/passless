# Agent passkey registration

> **EXPERIMENTAL.** Agent registration is implemented but not yet validated for production use.

An agent can create a passkey at a site (`navigator.credentials.create()`) through the managed
browser, under a rule you write. The daemon creates the key and stores the credential; the agent never
sees it. Use it to enrol an automation account once, then switch registration off.

## How it works

```text
page create() -> managed Chromium (webAuthenticationProxy) -> sign-proxy relay -> daemon
daemon: bearer and session -> origin and RP check -> rule -> excludeCredentials check
        -> audit reservation -> key generation (software or TPM) -> store -> audit terminal -> response
```

Registration shares the interception, transport and session model of sign-in
([Security](agents/security.md)). Its bearer is bound to the browser lease: when the browser exits or
the lease is revoked, the bearer stops working (`401 invalid_bearer`, audited as `policy.deny` with
reason `bearer_revoked`). There is no HTTP `/register` endpoint, no operator-minted enrollment grant
and no per-ceremony intent command.

## Allow registration

Registration is denied unless an **exact-RP** rule opts in. A wildcard rule never permits it.

```toml
[[agents.profiles.enroll.rules]]
rp_id = "git.example.com"
register = "allow"          # or "request" for a one-time prompt
authenticate = "allow"
```

- `register = "allow"`: the agent may create one passkey per ceremony with no prompt.
- `register = "request"`: a notification asks you each time. Approval permits exactly one registration,
  by the ceremony that asked; afterwards Passless stores `authenticate = allow` for that RP
  ([Rules](agents/rules.md#request-escalation)). `authenticate` must be `allow` or `request`.
- In `same-user` mode the new passkey goes into your own credential store, so the profile must also be
  listed in `acknowledge_same_user_registration`. In `isolated` mode it goes into the profile's store.

Then let the agent drive the browser ([Quick start](agents/quick-start.md)) and register through the
site's own "add a passkey" flow. Bring the page to the front: Chrome rejects `create()` from a
background tab.

## After enrollment

Set `register = "deny"` and reload the policy (`passless agent-admin policy reload <profile>`).
Authentication keeps working. The credential is immediately usable for sign-in in the same session.

## Audit

Every attempt is audited with the profile, RP, origin, matched rule, decision, credential reference and
result, and a reservation is written before the key exists
([Audit](agents/audit.md)).

## Key generation

- **Software backend**: the daemon generates the key and stores it in the credential store.
- **TPM backend**: the key is generated and sealed by the TPM and does not leave it.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Page gets `NotAllowedError` | No exact rule with `register = "allow"` or `"request"`, a denied or timed-out prompt, or a background tab. Check the audit. |
| Page gets `InvalidStateError` | The site's `excludeCredentials` matched an existing credential. Delete the old one or use another account. |
| Page gets `NotSupportedError` | The request asked for an unsupported extension, enterprise attestation or only unsupported algorithms. |
| `401 invalid_bearer` / `bearer_revoked` | The browser exited or its lease was revoked. Start a new session. |
| Page failed but a credential exists | The tab was not in front. The audit shows the registration; delete the orphan with `passless agent-admin credential delete <ref> --confirm`. |
| Key generation failed | TPM: check it is accessible. Software: check the daemon log. |
| Origin errors | The page must be served over HTTPS (or `http://localhost` for an exact `localhost` rule), on the RP's own origin. |

Testing: [Registration testing](AGENT_REGISTRATION_TESTING.md).
