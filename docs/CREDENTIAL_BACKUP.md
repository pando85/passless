# Credential Backup

Passless uses the word "backup" for two related but distinct things. This page covers both and
explains how they interact:

1. **Backup eligibility** — a WebAuthn credential property (the `BE`/`BS` flags) that tells a
   relying party whether a credential may be backed up or is multi-device. Controlled by the
   `enable_credential_backup` option.
2. **Encrypted backup & restore** — the Passless feature that exports a single software credential
   as an opaque OpenPGP bundle (`passless client backup` / `passless client restore`).

## Backup eligibility (BE / BS flags)

Every WebAuthn registration and assertion carries an authenticator-data flags byte. Two bits
describe backup status:

| Bit | Name | Meaning |
|-----|------|---------|
| `0x08` | BE (Backup Eligible) | The credential *may* be backed up / synced (a multi-device credential). |
| `0x10` | BS (Backup State) | The credential *is currently* backed up. |

`BS` is only meaningful when `BE` is set. A credential that is not backup-eligible reports
`BE=0, BS=0` (a single-device credential).

### The `enable_credential_backup` option

```toml
[security]
# Default: false
enable_credential_backup = true
```

This single option controls two behaviors:

- It enables the encrypted backup/restore vendor commands described below.
- It sets the backup eligibility assigned to **newly registered** credentials:
  - `false` (default) → `NotEligible` → new credentials report `BE=0`.
  - `true` → `Eligible` → new credentials report `BE=1`.

It is also available as the `--enable-credential-backup` flag or the
`PASSLESS_ENABLE_CREDENTIAL_BACKUP` environment variable.

> [!IMPORTANT]
> `enable_credential_backup` only affects credentials registered **after** it is set. Changing it
> does **not** migrate credentials that already exist; each credential keeps the backup state it was
> created with. See [Pitfalls and troubleshooting](#pitfalls-and-troubleshooting).

### Why this matters: strict relying parties

The WebAuthn Level 3 specification requires that a credential's **BE flag never changes** over its
lifetime — a change can indicate cloning or state corruption. Strict relying parties enforce this
and **reject authentication** when the BE flag at assertion time differs from the value recorded at
registration. Kanidm is one such RP (it fails with `CredentialBackupEligibilityInconsistent`).

So if a credential was registered reporting `BE=1` and later asserts `BE=0` (or vice versa), a
strict RP denies the login even though the key material is unchanged. Lenient RPs ignore the flag
and are unaffected.

## Encrypted backup & restore

Passless can export a single **software-backed** credential as an OpenPGP-encrypted bundle and
restore it later, on the same or another machine. The plaintext credential is serialized and
encrypted entirely inside the running authenticator process; the client only ever handles opaque
ciphertext.

### Prerequisites

- `enable_credential_backup = true` — the backup/restore commands are disabled otherwise.
- The Passless authenticator service must be **running**. Backup and restore are vendor CTAP
  commands processed by the authenticator and require user verification.
- A working `gpg` binary on `PATH`.
- For backup: a valid OpenPGP recipient (key ID, fingerprint, or email) present in your GPG
  keyring. For restore: the matching private key.
- The credential must be **software-backed**. TPM-resident / non-exportable credentials cannot be
  exported and are rejected.

### Back up a credential

```bash
# Find the credential ID
passless client list --domain example.com

# Export it to an encrypted bundle
passless client backup <CREDENTIAL_ID> \
  --recipient you@example.com \
  --output-file example.com-passkey.gpg \
  --yes-i-understand-this-exports-a-passkey
```

- `<CREDENTIAL_ID>` is the credential ID in hexadecimal (from `passless client list` or `show`).
- `--recipient` is the OpenPGP recipient (key ID, fingerprint, or email).
- `--output-file` is where the encrypted bundle is written.
- The confirmation flag is required to acknowledge that a passkey is being exported.

You will be prompted for user verification (desktop notification or PIN). A successful backup also
marks the credential as backed up (`BS=1`).

### Restore a credential

```bash
passless client restore example.com-passkey.gpg \
  --yes-i-understand-this-restores-a-passkey

# To overwrite an existing credential with the same ID:
passless client restore example.com-passkey.gpg --replace \
  --yes-i-understand-this-restores-a-passkey
```

- The positional `<PATH>` is the bundle to restore.
- `--replace` overwrites an existing credential with the same ID; without it, restoring over an
  existing ID fails.
- Restore decrypts with your GPG private key (you may be prompted for its passphrase).

### Bundle format and security

The bundle is standard OpenPGP ciphertext wrapping a small CBOR envelope
(`passless-credential-backup`, format version 1). Plaintext credential material exists only inside
the authenticator process and is zeroized after use; bundles are capped at 64 KiB. Treat a bundle as
sensitive: anyone holding the recipient private key can recover the passkey.

## Pitfalls and troubleshooting

### "Credential backup eligibility has changed" — a strict RP suddenly rejects a credential

This is the BE-consistency check described above: the BE flag the authenticator now reports differs
from what the RP stored at registration. The credential still works at lenient RPs.

The most common cause is **running more than one Passless version against the same credential
store**. The backup state is stored per credential. A Passless build that predates this field does
not write it, so when a newer build reads that credential the field falls back to its default
(`NotEligible`, `BE=0`). If the RP had recorded `BE=1`, the next assertion is rejected.

**Fix:** re-register the credential at the affected RP. The new registration records the current BE
value and the mismatch is resolved permanently.

To avoid recurrence:

- Run a single Passless version against a given store; do not alternate old and new binaries.
- Keep `enable_credential_backup` stable. Flipping it does not touch existing credentials, so it
  creates a mix of `BE=0` and `BE=1` credentials over time.
- If you intentionally change your backup posture, re-register the affected credentials at strict
  RPs (such as Kanidm) afterwards.

### Backup is rejected as unsupported

Only software-backed credentials can be exported. Credentials whose keys live in a TPM (the portable
TPM backend) are non-exportable by design and cannot be backed up with this feature.
