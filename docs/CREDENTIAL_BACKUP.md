# Credential Backup

Passless uses the word "backup" for two related but distinct things:

1. **Backup eligibility** — the WebAuthn `BE`/`BS` credential state.
2. **Encrypted backup and restore** — Passless vendor commands that export one software credential as an opaque encrypted bundle and restore it later.

The encrypted export path is disabled by default and never sends plaintext credential key material to the client process.

## Backup eligibility (BE / BS)

Every registration and assertion includes authenticator-data flags describing credential backup state:

| Bit | Name | Meaning |
|-----|------|---------|
| `0x08` | BE (Backup Eligible) | The credential may be backed up. |
| `0x10` | BS (Backup State) | The credential is currently backed up. |

Valid states are:

- `BE=0, BS=0` — single-device / not backup eligible.
- `BE=1, BS=0` — backup eligible, not yet backed up.
- `BE=1, BS=1` — backup eligible and backed up.

`BE=0, BS=1` is invalid.

### Enabling backup eligibility

```toml
[security]
enable_credential_backup = true
```

The option is `false` by default. It does two things:

- enables Passless backup/restore vendor commands;
- makes **newly registered** software credentials backup eligible (`BE=1`).

Existing credentials are not migrated. In particular, a credential created with `BE=0` is not exportable: Passless refuses the backup instead of changing its BE bit after registration. This is required because WebAuthn backup eligibility is invariant for a credential's lifetime and strict relying parties can reject a credential whose BE value changes.

The same setting is available as `--enable-credential-backup` and `PASSLESS_ENABLE_CREDENTIAL_BACKUP`.

## Security model

Backup/restore uses Passless vendor CTAP commands (`0x43` and `0x44`) and the normal credential-management PIN/UV authorization path. The CLI additionally requires an explicit acknowledgement flag for export and restore.

The important boundary is the running authenticator:

- credential plaintext, private signing key, `credRandom`, RP/user metadata and counters are serialized only inside the authenticator process;
- the complete portable credential source is encrypted **in-process with AES-256-GCM**;
- the client receives only the encrypted bundle plus a digest token used by the two-phase durable-backup commit;
- recipient identifier, format version and cipher suite are authenticated as AEAD associated data;
- bundle ciphertext contains an explicit, versioned credential-source schema rather than the Rust `soft_fido2::Credential` serialization;
- private credential key material and wrapping keys are never placed in command-line arguments, temporary files, logs, or CTAP IPC messages;
- decrypted plaintext and loaded wrapping-key buffers are zeroized after use;
- TPM/non-exportable credential providers are rejected.

A successful export is two-phase. Passless first prepares the encrypted bundle. The client writes it with mode `0600`, fsyncs it, atomically renames it into place and fsyncs the parent directory. Only then does the client send a commit token back to the authenticator. The source credential changes from `BE=1, BS=0` to `BE=1, BS=1` only after that commit succeeds.

## Wrapping keys

`--recipient` identifies an **authenticator-local wrapping key**, not secret key material. The same key must be provisioned on every Passless authenticator that should be able to restore the bundle.

By default keys live under:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/passless/credential-backup-keys/
```

The directory can be overridden with `PASSLESS_CREDENTIAL_BACKUP_KEY_DIR`.

For recipient `home-backup`, Passless reads:

```text
.../credential-backup-keys/home-backup.key
```

Recipient identifiers may contain ASCII letters, digits, `@`, `.`, `_`, `-`, and `+`, but no path separators or traversal components.

A key file must:

- be a regular file owned by the Passless user;
- not be a symlink;
- have no group/other permission bits (normally mode `0600`);
- contain either exactly 32 raw random bytes or 64 hexadecimal characters representing 32 bytes.

Example provisioning:

```bash
install -d -m 700 ~/.config/passless/credential-backup-keys
umask 077
head -c 32 /dev/urandom > ~/.config/passless/credential-backup-keys/home-backup.key
chmod 600 ~/.config/passless/credential-backup-keys/home-backup.key
```

Copy that key to the corresponding protected key directory on the restore target using a secure out-of-band channel. Treat it as a high-value secret: possession of the wrapping key plus a backup bundle is sufficient to recover the exported passkey.

## Back up a credential

First enable backup before registering the credential, so it is created with `BE=1`.

```bash
passless client list --domain example.com

passless client backup <CREDENTIAL_ID> \
  --recipient home-backup \
  --output-file example.com-passkey.pbackup \
  --yes-i-understand-this-exports-a-passkey
```

Requirements:

- the Passless authenticator service is running;
- `enable_credential_backup = true`;
- the credential is software-backed and already backup eligible;
- the selected wrapping-key file exists and passes ownership/permission checks;
- user verification or PIN authorization succeeds.

Passless refuses to overwrite an existing output file.

## Restore a credential

Provision the same wrapping key on the target authenticator, enable credential backup there, then run:

```bash
passless client restore example.com-passkey.pbackup \
  --yes-i-understand-this-restores-a-passkey
```

If a credential with the same ID already exists, restore fails by default. Replacement must be explicit:

```bash
passless client restore example.com-passkey.pbackup \
  --replace \
  --yes-i-understand-this-restores-a-passkey
```

A restored credential remains backup eligible and is marked backed up (`BE=1, BS=1`). Restore preserves the credential ID, RP and user data, signing key, algorithm, sign counter, discoverability, `credProtect`, `credRandom`, creation timestamp and backup eligibility.

Tampered bundles, malformed metadata, unsupported versions and the wrong wrapping key fail before credential installation.

## Bundle format

The current outer bundle format is version 2. It is CBOR with non-secret metadata and AEAD ciphertext:

```text
magic      = "passless-credential-backup"
version    = 2
cipher     = "AES-256-GCM"
recipient  = wrapping-key identifier
nonce      = 96-bit random nonce
ciphertext = encrypted portable credential source + GCM tag
```

`magic`, `version`, `cipher`, and `recipient` are authenticated as associated data. The encrypted payload contains its own format version, Passless source AAGUID/version metadata, and a stable credential-source schema.

Bundles are capped at 64 KiB.

### Draft v1 / OpenPGP bundles

The earlier implementation merged in PR #383 used an external `gpg` subprocess and serialized the internal `soft_fido2::Credential` representation directly. That draft format is intentionally **not accepted** by format v2: accepting it would reintroduce the plaintext-IPC boundary that this format removes.

If you created a v1 bundle, restore it with a pre-v2 Passless build in a controlled environment and immediately re-export the credential using format v2. Unsupported/legacy input otherwise fails closed as an invalid bundle.

## Failure behavior

Common failures are deliberate and fail closed:

- backup feature disabled → vendor command is unsupported;
- non-exportable/TPM credential → export rejected;
- credential has `BE=0` → export rejected without changing BE;
- missing/insecure wrapping-key file → crypto unavailable/invalid input;
- wrong wrapping key → authenticated decryption failure;
- modified ciphertext or recipient metadata → authenticated decryption failure;
- malformed/unknown bundle version → invalid bundle;
- restore ID collision without `--replace` → collision error;
- output path already exists → client refuses overwrite.
