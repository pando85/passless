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

The command prints the level of each credential before and after. Raising a level works the
same way. Only the level changes: the key, signature counter, user information and timestamps
are kept.

It is authorized like `passless client delete` and `rename`: the running authenticator asks for
your PIN, or for built-in user verification (the desktop notification) when no PIN is set. Unlike
those two, it has no path without that verification. Agent sessions cannot reach it. Credentials
are rewritten through the normal storage path, so the `pass` backend re-encrypts and commits
(and pushes, if configured), and the TPM backend reseals.

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

**Trade-off.** At level 1 the key needs only user presence (the notification prompt, or
whatever `security.user_verification_authentication` allows), not a PIN. Anyone who can sign
through your running authenticator and approve the prompt can use that key. Level 3 is the
stronger setting; lower it only for keys where a presence-only prompt per signature is what
you want. Raising it again later is the same command with `--level 3`.
