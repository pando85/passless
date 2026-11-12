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

Registration is denied unless a rule opts in. `register = "allow"` needs an **exact-RP** rule and is
invalid on the wildcard. The wildcard can only ask: see [Registration at unlisted
sites](#registration-at-unlisted-sites).

```toml
[[agents.profiles.enroll.rules]]
rp_id = "git.example.com"
register = "allow"          # or "request" for a one-time prompt
authenticate = "allow"
```

- `register = "allow"`: the agent may create one passkey per ceremony with no prompt.
- `register = "request"`: a notification ("CREATE A NEW PASSKEY? (not a sign-in)", with **Register once**
  and **Deny**) asks you each time. Approval permits exactly one registration, by the ceremony that
  asked; afterwards Passless stores `authenticate = allow` for that RP
  ([Rules](agents/rules.md#request-escalation)). `authenticate` must be `allow` or `request`.
- In `same-user` mode the new passkey goes into your own credential store, so the profile must also be
  listed in `acknowledge_same_user_registration`. In `isolated` mode it goes into the profile's store.

Then let the agent drive the browser ([Quick start](agents/quick-start.md)) and register through the
site's own "add a passkey" flow. Bring the page to the front: Chrome rejects `create()` from a
background tab.

## Registration at unlisted sites

To let the agent also ask for a passkey at a site no exact rule lists, give the `*` rule
`register = "request"` in a `same-user` profile. It needs `acknowledge_global_same_user`,
`acknowledge_same_user_registration` and `acknowledge_global_registration`, and is bounded by
`max_wildcard_registrations` (default 4), `wildcard_registration_prompts_per_day` (default 3) and a
profile-wide cooldown after a deny or timeout. The prompt says the site is not on your list and how many
passkeys your store already holds for it. After one approved registration the agent signs in at that
site with its own passkey only, without asking. With a shared Unix user this is a convenience, not a
security boundary. Details: [Rules](agents/rules.md#registration-at-unlisted-sites).

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
| Page gets `NotAllowedError` | No rule with `register = "allow"` (exact) or `"request"` (exact, or `*` with the acknowledgements), a denied or timed-out prompt, a refusal without a prompt (`wildcard_registration_cap`, `wildcard_registration_rate`, `wildcard_registration_cooldown`), or a background tab. Check the audit. |
| Page gets `InvalidStateError` | The site's `excludeCredentials` matched an existing credential. Delete the old one or use another account. |
| Page gets `NotSupportedError` | The request asked for an unsupported extension, enterprise attestation or only unsupported algorithms. |
| `401 invalid_bearer` / `bearer_revoked` | The browser exited or its lease was revoked. Start a new session. |
| Page failed but a credential exists | The tab was not in front. The audit shows the registration; delete the orphan with `passless agent-admin credential delete <ref> --confirm`. |
| Key generation failed | TPM: check it is accessible. Software: check the daemon log. |
| Origin errors | The page must be served over HTTPS (or `http://localhost` for an exact `localhost` rule), on the RP's own origin. |

Testing: [Registration testing](AGENT_REGISTRATION_TESTING.md).
