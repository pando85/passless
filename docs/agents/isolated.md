# Isolated mode

> **EXPERIMENTAL** — Agent mode is not yet validated for production use.

Isolated profiles use agent-owned credentials with independent credential storage, verification/PIN state, key-provider state, operation locking, and revocation lifecycle. They cannot enumerate or sign with the human credential namespace.

Use isolated mode as the default choice for unattended automation when the relying party can support a separate automation account or service identity.

## Trust model

An isolated agent may still be fully autonomous, but it authenticates as an agent-owned RP identity rather than the human's existing passkey identity.

```text
Passless daemon
  ├─ human credential backend
  │    └─ unavailable to isolated profile
  │
  └─ isolated profile: release-bot
       ├─ isolated credential backend
       ├─ isolated verification/PIN state
       ├─ configured key provider (software/pass/TPM)
       ├─ exact RP/action policy
       ├─ bounded session / one-shot operation state
       └─ audit
```

Autonomy is an action policy, not a credential-ownership mode. An isolated profile can use:

- `deny` — operation not allowed;
- `supervised` — human confirmation/evidence;
- `autonomous` — agent-derived UP/UV after the bound agent/session gates succeed.

Agent-derived evidence is not human interaction and must be recorded as `agent`, not `human`, in operator/audit surfaces.

## Example autonomous profile

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless-agent/audit"

[agents.profiles.release-bot]
mode = "isolated"
principal_user = "passless-release"
max_session_ttl = 300
max_operations = 8
credential_selection = "single"

[[agents.profiles.release-bot.rules]]
rp_id = "github.com"
register = "autonomous"
authenticate = "autonomous"

[agents.profiles.release-bot.storage.local]
path = "/var/lib/passless-agent/release-bot/credentials"
pin_path = "/var/lib/passless-agent/release-bot/pin"

[agents.profiles.release-bot.device]
name = "passless-agent-release"
phys = "release-phys"
uniq = "release-uniq"
vendor_id = 4660
product_id = 22137
```

The expanded autonomous policy is:

```toml
authenticate = {
  authorization = "allow",
  user_presence = "agent",
  user_verification = "agent"
}
```

The legacy evidence spelling `policy` may still parse as an alias, but current configuration, documentation, and audit terminology should use `agent`.

## Storage isolation

Each isolated profile has its own backend namespace. Supported backends follow the Passless build/configuration: local, pass-backed, and TPM where available.

Validation rejects overlapping roots between:

- isolated profiles;
- isolated credential and PIN state where overlap is unsafe;
- agent audit state;
- the human backend state.

This is a security invariant, not merely a directory-layout preference.

For portable TPM credentials, the configured TPM provider remains the signer; agent mode must not silently substitute software keys.

## One-shot intents

The isolated compatibility/native ceremony path requires an intent immediately before the matching WebAuthn operation.

### Registration

```bash
passless agent --profile release-bot intent create register \
  --rp github.com \
  --reason "initial release-bot enrollment"
```

The intent is bound to the requested action/RP and current principal/policy state. An autonomous rule does not require per-operation administrator approval, but the ceremony still passes the daemon's policy, storage, audit, and operation gates.

### Authentication

```bash
passless agent --profile release-bot intent create authenticate \
  --rp github.com \
  --credential <credential-ref-hex> \
  --reason "release push"
```

The credential reference is non-secret. The private key remains in the isolated backend/key provider.

Treat success, denial, cancellation, expiry, and terminal failure as consuming the operation authority. Create a new intent for a genuinely new operation rather than replaying a completed one.

## Managed browser path

Isolated profiles can also use the daemon-managed browser/extension pipeline where configured. The production extension forwards bounded WebAuthn requests to the daemon; it does not receive private keys or PINs.

For the managed browser path:

- origin/top-origin come from browser extension sender metadata rather than page claims;
- RP/origin relationship is revalidated in the daemon;
- conditional mediation/passkey autofill remains native;
- unverifiable cross-origin Permissions Policy delegation remains native;
- session operation budgets and replay detection apply;
- audit gates credential use.

The managed browser session is still application authority. After an isolated credential signs into its RP account, an agent controlling that browser can perform whatever actions that isolated account is allowed to perform.

## Fully unattended workflow

1. Create the principal Unix identity and isolated storage roots.
2. Configure the narrowest exact RP rules required by the automation.
3. Keep `max_session_ttl` and `max_operations` small.
4. Validate before launch:
   ```bash
   passless agent-admin profile check release-bot
   passless agent-admin policy check release-bot
   ```
5. Launch the principal:
   ```bash
   passless agent run --profile release-bot -- /usr/local/bin/agent-command
   ```
6. Inside the principal session, inspect:
   ```bash
   passless agent --profile release-bot doctor
   passless agent --profile release-bot capabilities
   passless agent --profile release-bot instructions
   ```
7. Create the required one-shot intent immediately before each isolated native ceremony, or use the managed browser path according to the profile/runtime configuration.
8. Review audit and RP-side account/session state after enrollment or sensitive automation.

## Registration

Registration creates identity state. Allow it only where unattended enrollment is actually intended.

After initial enrollment, a common safer policy is:

```toml
[[agents.profiles.release-bot.rules]]
rp_id = "github.com"
register = "deny"
authenticate = "autonomous"
```

Restart the daemon after editing on-disk configuration. `agent-admin policy reload` recompiles the daemon's current in-memory configuration snapshot; it is not a configuration-file reload mechanism.

## Credential selection

`credential_selection = "single"` is the safest default. It fails closed if discoverable authentication leaves multiple eligible isolated credentials.

`first-matching`, `newest`, and explicit credential references are deterministic alternatives. Prefer explicit identity/account mapping when selecting the wrong RP account would be consequential.

## Revocation

List and revoke isolated credentials with the administrator CLI:

```bash
passless agent-admin credential list --profile release-bot
passless agent-admin credential revoke <credential-ref> --confirm
passless agent-admin credential delete <credential-ref> --confirm
```

Local revocation/deletion does not automatically revoke RP-side sessions or remove the credential from the RP account. Use the RP's own controls as well when necessary.

Disable the entire profile immediately with:

```bash
passless agent-admin profile disable release-bot
```

## Boundaries retained under autonomy

Even with `authenticate = "autonomous"`:

- isolated code cannot select the human credential namespace;
- policy is evaluated for the concrete action/RP;
- the current principal/session and policy generation remain relevant;
- credential scope/selection is daemon-controlled;
- replay and operation-budget controls remain active on the managed browser path;
- audit reservation is required before credential use/creation;
- the principal cannot edit administrator policy or gain the admin socket merely because authentication is autonomous.

See [security.md](security.md) for the shared threat model and [operations.md](operations.md) for browser/session authority, audit, and recovery guidance.
