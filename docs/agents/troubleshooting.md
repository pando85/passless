# Agent troubleshooting

> **EXPERIMENTAL** — Agent mode is not yet validated for production use.

Common issues and diagnostics for the current `same-user` and `isolated` modes.

## Agent support is disabled

**Symptom:** `passless agent run` or `passless agent-admin` fails with "agent support is disabled" or similar.

**Diagnosis:**

```bash
passless agent-admin profile list
# Check that [agents].enabled = true in the configuration file.
```

**Fix:** Set `enabled = true` in `[agents]`, configure `audit_path`, and restart the daemon.

## Profile not found

**Symptom:** `passless agent run --profile <name>` fails with "profile not found".

**Diagnosis:**

```bash
passless agent-admin profile list
```

**Fix:** Ensure the profile exists under `[agents.profiles.<name>]`. If it was disabled at runtime, re-enable it with the administrator CLI.

## Configuration validation errors

**Symptom:** The daemon fails to start or `passless agent-admin profile check` reports errors.

Common current errors include:

| Error / condition | Cause | Fix |
|---|---|---|
| `same-user mode uses the human backend and must not specify storage` | Same-user profile has a profile-specific storage section | Remove the profile storage configuration; same-user reuses the already-open human backend |
| `isolated mode requires storage backend configuration` | Isolated profile has no separate storage | Add an isolated local/pass/TPM storage backend |
| `isolated mode requires a complete device identity` | Isolated UHID identity is incomplete | Configure `device.name`, `phys`, `uniq`, vendor ID, and product ID |
| `explicit rules cannot be combined with legacy rp_ids...` | New rule syntax is mixed with migration syntax | Use explicit `[[agents.profiles.<name>.rules]]` entries only |
| `wildcard RP scope '*' is only supported in same-user mode` | Global scope used by an isolated profile | Replace `*` with exact RP rules |
| `wildcard RP scope '*' requires credential_refs to be omitted` | Global same-user scope is mixed with static credential references | Remove `credential_refs` or, preferably, replace `*` with exact RP rules and explicit credential scope |
| `wildcard RP scope '*' must deny registration` | Global registration was enabled | Keep wildcard registration denied; registration requires exact RP policy |
| invalid RP / public suffix / wildcard error | RP is a URL, IP, public suffix, partial wildcard, or otherwise invalid | Configure an exact WebAuthn RP ID such as `github.com`; `*` is the only global policy sentinel and only for same-user authentication |
| device identity collision | Isolated device identity matches the human endpoint or another profile | Change the isolated device identity |
| agent roots overlap | Audit, isolated storage, PIN, or human state paths overlap | Use independent roots |
| `unknown field` | Invalid, removed, or misspelled configuration | Remove it and check [configuration.md](configuration.md) |
| invalid mode `delegated-session` | The old experimental mode was removed | Migrate human-credential use to `same-user` and review its trust model; use `isolated` for a separate RP identity |

**Diagnosis:**

```bash
passless agent-admin profile check <profile>
passless agent-admin policy check <profile>
```

For same-user profiles, also review:

```bash
passless agent run --profile <profile> -- sh -c \
  'passless agent --profile <profile> capabilities'
```

The capabilities view identifies human-identity and global-wildcard authority explicitly.

## Same-user profile unexpectedly has broad authority

**Symptom:** `capabilities` reports `acts_as_human: true`, or `wildcard_rp_scope: true`.

**Diagnosis:** This is the intended meaning of `same-user`: it exercises the human credential/RP identity within the configured policy. `rp_id = "*"` expands authentication policy to any valid concrete RP for which the human backend contains a matching credential.

**Fix:**

- Prefer `isolated` when a separate RP account is acceptable.
- Replace `*` with exact RP rules.
- Add explicit credential references where practical.
- Keep session TTL and operation budget small.
- Keep same-user registration denied after enrollment.

Remember that after successful authentication Passless does not restrict application actions inside the resulting RP browser session.

## Browser fails to start

**Symptom:** Managed browser launch fails.

**Diagnosis:**

```bash
passless agent-admin profile check <profile>
passless agent-admin browser launch --profile <profile>
```

Check the configured browser command and, for same-user profiles that use an explicit browser runtime/user boundary, verify the runtime root ownership and mode.

**Fix:**

- Ensure `browser_command` names an installed Chromium/Chrome-compatible browser where the managed extension path is used.
- Do not inject conflicting `--remote-debugging-*` or extension flags; Passless owns those settings.
- Ensure `browser_runtime_root`, when configured, is owned by the expected browser user and has the required restrictive permissions.
- Run `profile check` to detect stale/unsafe runtime state.

## Browser works, but WebAuthn stays native

**Symptom:** A WebAuthn request opens the normal browser/security-key UI instead of completing through the agent path.

This can be intentional.

Passless deliberately leaves these cases native:

- conditional mediation/passkey autofill (`mediation = "conditional"`);
- a cross-origin frame when browser Permissions Policy delegation cannot be verified;
- policy that requires human interaction;
- unsupported/invalid browser request semantics.

**Fix:** Do not bypass the native fallback with a virtual authenticator or private-key injection. Verify the RP flow, frame Permissions Policy, and current profile policy instead.

## Human confirmation never appears or fails closed

**Symptom:** A supervised operation returns an interaction/notification error.

**Diagnosis:** The confirmation boundary requires a notification server that can provide distinct Approve and Deny actions. Unsupported or unqueryable notification-server behavior fails closed.

**Fix:**

- Test on the actual desktop environment.
- Check daemon logs for `notification_unsupported`, `server_capability_rejected`, or render errors.
- Do not work around the prompt by passing approval or PIN material through stdin, environment variables, chat, or page content.

Agent/page-provided strings are sanitized and shown only as explicitly untrusted informational context; make the decision from the trusted RP/action fields.

## Authentication stops after repeated ceremonies

**Symptom:** The browser is still running but further WebAuthn operations return replay or operation-budget errors.

**Diagnosis:** Each short-lived session has a bounded shared WebAuthn operation budget, and identical completed request bodies are rejected as replays.

**Fix:** Treat `replayed_operation` as terminal for that operation. Treat `operation_budget_exhausted` as terminal for the session and launch a new bounded session if the operator still intends the task. Repeated retries are not a recovery strategy.

## CDP client cannot connect

**Symptom:** Playwright or another external browser automation client cannot attach.

**Diagnosis:**

```bash
passless agent --profile <profile> browser-status
```

The plain status output includes `cdp_endpoint` when one is exposed. External attachment requires profile `browser_cdp_expose = "port"`; pipe mode is daemon-mediated.

**Fix:** Enable port mode only when full external control of the authenticated managed-browser session is intentional. Do not expose the loopback endpoint to untrusted local processes.

## Principal cannot access admin commands

**Symptom:** `passless agent-admin` commands fail inside a principal session.

**Diagnosis:** This is expected. Principal sessions do not receive the administrator interface.

**Fix:** Run administrator commands outside the principal session under the daemon administrator identity.

## Audit verification fails

**Symptom:** `passless agent-admin audit verify` reports a hash-chain discontinuity.

**Fix:**

1. Do not treat the audit trail as trustworthy until the cause is understood.
2. Preserve the existing audit files.
3. Investigate sequence gaps and hashes.
4. Repair the audit storage before re-enabling agent work.

The local hash chain is not externally anchored; host root remains capable of rewriting local state.

## Quarantined browser runtime

**Symptom:** Browser cleanup did not complete and stale runtime state is detected.

**Diagnosis:**

```bash
passless agent-admin profile check <profile>
```

**Fix:** Inspect the reported runtime path and process identity before removing quarantined state. Do not blindly reuse an unverified stale browser profile.

## Daemon restart loses active sessions

**Symptom:** Active agent sessions no longer work after daemon restart.

**Diagnosis:** This is expected. Session capabilities, operation state, grants/intents, and browser bindings are intentionally short-lived daemon state.

**Fix:** Re-run the profile pre-flight and launch a new principal/browser session. Do not replay old authorization material.

## RP session outlives the local browser lease

**Symptom:** The Passless lease/session ended, but the RP still considers its browser session authenticated.

**Diagnosis:** This is expected. Local capability/lease expiry does not revoke server-side RP sessions.

**Fix:** Use the RP's own session-revocation/logout controls after compromise or when explicit remote revocation is required.

## Isolated credential not found

**Symptom:** An isolated operation cannot resolve the requested credential reference.

**Diagnosis:**

```bash
passless agent-admin credential list --profile <profile>
```

**Fix:** Verify the non-secret credential reference and RP. Isolated profiles cannot use the human credential namespace.

## Same-user credential selection is ambiguous

**Symptom:** Discoverable authentication fails when more than one eligible human credential exists.

**Diagnosis:** The default `credential_selection = "single"` intentionally fails closed on ambiguity.

**Fix:** Prefer explicit credential references for account-sensitive RPs. `first-matching` and `newest` are deterministic convenience policies, not proof that the intended human account was selected.

## Kernel or distribution not supported

**Symptom:** Agent mode fails with missing kernel/IPC/device features.

**Diagnosis:** Review [operations.md](operations.md#kernel-requirements) and `profile check` output.

**Fix:** Use a supported Linux environment providing the required UHID/hidraw, process-management, IPC, and isolation primitives for the configured mode/path.

## Further help

- [Agent overview](README.md)
- [Security model](security.md)
- [Configuration reference](configuration.md)
- [Same-user mode](same-user.md)
- [Isolated mode](isolated.md)
- [Operations](operations.md)
