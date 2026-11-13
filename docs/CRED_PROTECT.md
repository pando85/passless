# Credential protection level (credProtect)

`credProtect` decides when a stored credential may be used without user verification (UV):

| Level | Name | Used without UV |
|-------|------|-----------------|
| 1 | `userVerificationOptional` | always (presence only) |
| 2 | `userVerificationOptionalWithCredentialIDList` | only when the request names the credential |
| 3 | `userVerificationRequired` | never |

The level is fixed when a credential is created. Passless can change it afterwards:

```bash
# One credential
passless client set-cred-protect --id <CREDENTIAL_ID> --level 1

# Every credential of a relying party (lists them and asks first; --yes skips the question)
passless client set-cred-protect --rp ssh: --level 1

# Machine-readable output (--rp then needs --yes)
passless client -o json set-cred-protect --rp ssh: --level 1 --yes
```

The credentials are looked up and shown first, with the device that was selected, their RP, user
and current level. Lowering asks for confirmation unless `--yes` is given, for `--id` as well as
`--rp`; raising never asks. With `-o json` a question cannot be asked, so `--yes` is required for
`--rp` and for lowering with `--id`. The command then prints the level of each credential before
and after. Only the level changes: the key, signature counter, user information and timestamps
are kept.

## Authorization and consent

The change goes through the running authenticator and is authorized like the credential
management commands behind `passless client delete` and `rename`: a pinUvAuthToken with the `cm`
permission. That is your PIN when one is set, otherwise built-in user verification (the desktop
notification). Standard CTAP credential management also always requires a `pinUvAuthParam`; only
the `passless client` helpers for `list`, `delete` and `rename` may try a request without one.
`set-cred-protect` never does: a request without a valid token is refused whether or not a PIN is
set. The signed request names the exact credentials and the level. Agent sessions cannot reach
the command.

- **PIN set:** typing the PIN is the consent. No built-in UV token is issued while a PIN is set,
  so there is no extra prompt.
- **No PIN, lowering:** the built-in UV prompt for the token is generic ("User Verification
  Required, Credential Management") and does not say what it buys, so the authenticator asks a
  second, dedicated question built from its own storage after it has read the credentials and
  before it writes anything: "Lower credential protection: N credential(s) for ssh:: 3 -> 1
  (presence only)". Deny, close, timeout or a failure to show it refuses the change.
- **No PIN, `PASSLESS_INTERACTION_MODE=automatic`:** every prompt is auto-approved, so lowering is
  refused outright with an error. Set a PIN or use the desktop interaction mode.
- **Raising** needs no extra prompt.

Credentials are rewritten through the normal storage path, so the `pass` backend re-encrypts and
commits (and pushes, if configured), and the TPM backend reseals.

## When the command fails

A batch is checked first (every credential must exist) and then written one credential at a
time. If a write fails, the authenticator tries to restore the ones already written, but that
rollback is best effort and can fail too, and on `pass` the Git commit of the operation may
already exist. After any error, check the real state:

```bash
passless client list -d ssh:
```

Wire format: vendor CTAP command `0x45`, documented in `cmd/passless/src/credential_protection.rs`.
It is not announced in `authenticatorGetInfo`, and standard credential management is unchanged.

## SSH keys and always_uv

OpenSSH `ed25519-sk` and `ecdsa-sk` keys are enrolled with `ssh-keygen -t ed25519-sk -O resident`.
If user verification ran during enrollment, the key is stored with credProtect level 3. That
happens with `security.always_uv = true` (the default), and with every release build from v0.16
to v0.21 because of a bug. A level 3 credential needs UV for every signature, however
`always_uv` is set later.

If you then set `always_uv = false` and have a PIN, each SSH signature with such a key asks for
the PIN. Two ways out:

- **Re-enroll the key** (`ssh-keygen -t ed25519-sk -O resident` again, replace the public key
  where it is installed) after changing the setting. Check the result with
  `passless client list -d ssh:`, which shows each credential's level. This keeps level 3
  protection for the keys you do not touch, and costs a new key pair.
- **Lower the level of the existing key**, which keeps the key pair and every public key
  already deployed:

  ```bash
  passless client list -d ssh:
  passless client set-cred-protect --rp ssh: --level 1
  ```

  Use `--id` instead of `--rp` to change one key only.

**Trade-off.** At level 1 the key needs only user presence, not a PIN. What presence means is
decided by `security.user_verification_authentication`: with it set to `false`, level 1 means
**silent signing by any process that can reach the authenticator's hidraw device**, with no
prompt at all. Level 3 is the stronger setting; lower it only for keys where you accept that.
Raising it again later is the same command with `--level 3`.

**Lowering has no effect while `security.always_uv = true`.** The authenticator then forces user
verification whatever a credential's level, so a lowered SSH key keeps asking for the PIN. Lower
the level together with `always_uv = false`, which is the situation this command is for.
