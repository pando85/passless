# Portable TPM Backend

> **Status: Experimental.** The portable TPM backend is new and has only been validated against
> software TPMs (swtpm). Cross-vendor hardware TPM interoperability has not been tested. Do not
> rely on it as the sole backup for high-value credentials without independent offline backups.

## Overview

The portable TPM backend stores WebAuthn credential signing keys as **TPM-resident, non-exportable
objects** that can be synchronized across multiple TPMs provisioned from the same recovery seed.

This differs fundamentally from the legacy TPM backend:

| | Legacy TPM backend | Portable TPM backend |
|---|---|---|
| Signing key lifetime | Generated in software, sealed to device-local TPM primary | Generated inside the TPM, never leaves the TPM in plaintext |
| Key material in host memory | Present after unseal (cached for credential lifetime) | Never present — signing happens inside the TPM via `TPM2_Sign` |
| Portability | Bound to the device that created the seal | Portable across any TPM provisioned from the same recovery seed |
| Storage parent | Transient device-local RSA primary (`fixedTPM=true`) | Persistent ECC P-256 parent at handle `0x81000001` (`fixedTPM=false`) |
| Sync model | None — credentials are device-local | Sync the on-disk credential directory (e.g. via `pass`, git, syncthing) |

The portable backend is selected with `--backend-type tpm --tpm-portable`.

## Provisioning

Before the portable backend can be used, a **portable parent** must be provisioned on each TPM.
The parent is derived deterministically from a 32-byte (256-bit) recovery seed, so every TPM
provisioned with the same seed ends up with an identical parent key at persistent handle
`0x81000001`.

### Commands

```bash
# Generate a fresh random seed, print it ONCE, and provision the parent
passless tpm provision --generate

# Provision with a seed read from a file (hex-encoded, 64 chars)
passless tpm provision --seed-file seed.hex

# Provision with a seed piped from stdin (e.g. from password-store)
pass show fido2/seed | passless tpm provision --seed-stdin

# Interactive prompt (seed is not echoed)
passless tpm provision

# Show provisioning status
passless tpm status

# Remove the provisioned parent (requires --confirm)
passless tpm remove --confirm
```

All commands accept `--tpm-path PATH` and `--tpm-tcti TCTI` to target a specific TPM.

### Seed input

The recovery seed is a 32-byte value encoded as 64 hexadecimal characters. It is accepted through
exactly four channels — never as a positional or regular CLI argument:

1. `--generate` — the authenticator generates 32 random bytes via the OS CSPRNG, prints the hex
   seed to stderr exactly once, and warns that it will not be shown again.
2. `--seed-file PATH` — the hex seed is read from the first line of the file at `PATH`. A warning
   is printed if the file has group or other permissions set (recommend `chmod 600`).
3. `--seed-stdin` — the hex seed is read from stdin. Useful for piping from `pass` or other
   secret stores: `pass show fido2/seed | passless tpm provision --seed-stdin`.
4. Interactive prompt via `rpassword` — the seed is read without echo.

`--generate`, `--seed-file`, and `--seed-stdin` are mutually exclusive.

### What provisioning does

1. Derives an ECC P-256 private scalar and seed value from the recovery seed using HKDF-SHA256
   (salt `passless.portable.v1`, info labels `parent-ecc-key` and `parent-seed-value`).
2. Wraps the sensitive material using the TPM's storage primary as an import parent
   (`TPM2_Import` with ECDH+KDFe+KDFa+AES-128-CFB+HMAC).
3. Loads and persists the imported parent at owner-hierarchy persistent handle `0x81000001`.
4. Writes `portable_parent.json` into the storage directory containing the parent's public area,
   name, and persistent handle (used for verification and to detect an unprovisioned state).

Provisioning refuses to overwrite an existing parent. To re-provision, run
`passless tpm remove --confirm` first.

## Configuration & running

The portable backend is activated by combining `--backend-type tpm` with `--tpm-portable`:

```bash
# Hardware TPM
passless --backend-type tpm --tpm-portable --tpm-tcti device:/dev/tpmrm0

# swtpm (software TPM for testing)
passless --backend-type tpm --tpm-portable \
    --tpm-tcti "swtpm:path=$HOME/.local/run/swtpm-sock"
```

Equivalent environment variables:

| Variable | Purpose |
|---|---|
| `PASSLESS_BACKEND_TYPE` | Must be `tpm` |
| `PASSLESS_TPM_PORTABLE` | Set to `1` / `true` to enable portable mode |
| `PASSLESS_TPM_PATH` | Storage directory (default: `~/.local/share/passless/tpm`) |
| `PASSLESS_TPM_TCTI` | TCTI connection string (default: `device:/dev/tpmrm0`) |

TOML configuration:

```toml
[tpm]
path = "/home/user/.local/share/passless/tpm"
tcti = "device:/dev/tpmrm0"
portable = true
```

If the portable parent is not provisioned, the authenticator refuses to start with:

```
TPM portable parent is not provisioned. Run: passless tpm provision
```

## Recovery seed

The recovery seed is the single secret that controls the ability to provision new TPMs into the
portable credential set. Treat it with the same care as a master password.

### Backup expectations

- The seed is shown exactly once when `--generate` is used. Write it down on paper or store it
  in an offline password manager / safe.
- There is no way to recover the seed from a provisioned TPM. The TPM holds only the derived
  parent key material, not the seed itself.
- Anyone who obtains the seed can provision a new TPM and, given a copy of the synced credential
  directory, load and use every credential.

### Consequences of loss

If the recovery seed is lost and all provisioned TPMs are destroyed:

- New TPMs cannot be provisioned with the same parent.
- Existing synced credential blobs become unusable — they are sealed under a parent that no
  longer exists and cannot be reconstructed.
- You must re-register fresh passkeys at every relying party.

### Consequences of compromise

If an attacker obtains the recovery seed:

- They can provision their own TPM with the identical parent.
- If they also obtain a copy of the synced credential directory (e.g. from a git remote, backup,
  or synced filesystem), they can load and sign with every credential.
- There is no per-device cryptographic revocation: all devices provisioned from the same seed
  share the same parent, and the TPM cannot distinguish "authorized" from "cloned" parents.

### Rotation

Rotating the recovery seed requires:

1. Provisioning a new parent under the new seed (`passless tpm remove --confirm`, then
   `passless tpm provision --generate` with the new seed).
2. Re-registering every passkey at every relying party (the old credential blobs are sealed
   under the old parent and cannot be re-sealed without the old seed).

There is no in-place migration of credential blobs between parents.

## Threat model

### Protects against

- **Offline theft of synced credential files without the recovery seed and without a provisioned
  TPM.** The credential blobs are encrypted with AES-GCM under a key that is itself sealed to the
  portable parent. Without the parent (which requires the seed to import), the blobs are opaque.
- **Extraction of newly-generated signing keys from host memory.** The signing private key is
  generated by `TPM2_Create` inside the TPM and is never returned to the Passless process or to
  `soft-fido2` host memory. Signing is performed by `TPM2_Sign` inside the TPM; only the
  signature is returned.
- **Cold-boot, swap, and core-dump leakage of signing keys.** The signing key does not exist in
  process memory at any point. Passless still applies `mlockall`, core-dump prevention, and
  `PR_SET_DUMPABLE=0` as defense in depth for other sensitive material.
- **Copying a credential blob to a TPM that does not have the portable parent.** `TPM2_Load`
  will fail because the inner wrapper cannot be unwrapped without the parent's storage seed.
- **Exposure of opaque backup blobs.** Backed-up `.tpm` files reveal only the encrypted payload
  and the TPM public/private blobs; they do not reveal the signing key or the metadata AES key
  without the portable parent.

### Does NOT protect against

- **Recovery seed compromise combined with credential blob theft.** An attacker with both can
  provision a TPM and load every credential.
- **Full compromise of a provisioned machine.** An attacker who can invoke the authorized
  Passless process on a machine with a provisioned TPM can make it sign arbitrary messages.
- **Malicious kernel or firmware.** The kernel mediates access to `/dev/tpmrm0`; a compromised
  kernel can impersonate the TPM or intercept commands.
- **Revocation of a provisioned device.** There is no mechanism to revoke one device's parent
  without rotating the seed for all devices. All provisioned TPMs are cryptographically
  equivalent.
- **Rollback of synced metadata.** An attacker who can replace synced credential files with
  older versions can replay old credentials. The backend does not track a global monotonic
  version.
- **Loss of all provisioned TPMs combined with loss of the recovery seed.** Total, unrecoverable
  credential loss.

## Migration & compatibility

### Legacy TPM credentials

Credentials created with the legacy (non-portable) TPM backend remain fully readable. The legacy
backend seals each credential under a device-local RSA primary (`fixedTPM=true`, `fixedParent=true`);
those sealed files are not silently rewritten or migrated.

### Portable format

The portable backend uses a new on-disk format:

- Credential signing keys are stored as opaque `TpmKeyMaterial` JSON blobs containing the
  `TPM2B_PUBLIC`, `TPM2B_PRIVATE`, and uncompressed COSE public key.
- Credential metadata is sealed under the portable parent (not the device-local primary), so
  sealed records are portable.
- The provider ID is `tpm-portable-v1` with format version `1`.

### Migration path

There is no automated migration. To move a credential from the legacy backend to the portable
backend, **re-register** the passkey at the relying party while the authenticator is running in
portable mode. The relying party will issue a new credential bound to the portable TPM parent.

Legacy `.tpm` files are not silently rewritten. You can continue to use the legacy backend for
existing credentials while registering new credentials on the portable backend.

### On-disk layout

Both backends use the same directory layout: `{storage_dir}/{rp_id}/{cred_id_hex}.tpm`. The
portable backend additionally writes `portable_parent.json` at the storage root. Note that the
directory and file names expose the RP ID and credential ID in the clear on the filesystem; this
is a known limitation shared with the legacy backend.

## Signature counter

Portable credentials should use a **constant signature counter** enabled via
`--constant-signature-counter` (or `PASSLESS_CONSTANT_SIGNATURE_COUNTER=true`). The default is
`false` (mutable counter), which is problematic for portable mode.

Rationale: a mutable global signature counter cannot be safely synchronized across offline
devices. If device A increments the counter to 42 and device B increments it to 17 independently,
syncing the two state directories produces an inconsistent counter that relying parties may
reject as evidence of cloning. A constant counter avoids this class of sync hazard at the cost
of not providing RPs with clone-detection via counter regression.

**Recommendation:** Always enable `--constant-signature-counter` when using the portable TPM
backend.

Relying parties that strictly enforce monotonic signature counters will reject credentials from
any authenticator that can be used on multiple devices, including the portable TPM backend.

## Known limitations

- **ES256 only.** The TPM key provider supports COSE algorithm `-7` (ECDSA P-256 / SHA-256)
  exclusively. EdDSA (Ed25519, COSE algorithm `-8`) is not implemented — the TPM 2.0 command set
  used here does not expose an EdDSA signing path in the current `tss-esapi` binding.
- **TpmPinStorage is device-local.** PIN state (PIN value, retry counter, lockout) is sealed
  under the device's own hierarchy primary, not under the portable parent. PIN state does not
  sync across TPMs. Each provisioned TPM maintains its own independent PIN state.
- **Agent-mode portable storage is not wired.** The agent subsystem's storage factory
  (`cmd/passless/src/agent/storage_factory.rs`) always constructs the legacy (non-portable)
  `TpmStorageAdapter` for TPM-backed agent profiles. Agent profiles cannot currently use the
  portable backend; they fall back to device-local TPM storage.
- **Requires TPM 2.0 with ECC P-256 + ECDH.** The portable parent is an ECC P-256 storage key
  imported via `TPM2_Import` using ECDH for seed wrapping. TPMs that lack ECC P-256 or ECDH
  support (some older discrete TPMs, certain firmware TPM configurations) cannot use the
  portable backend.
- **Persistent handle `0x81000001` is hardcoded.** The portable parent occupies owner-hierarchy
  persistent handle `0x81000001`. If another application already uses this handle on your TPM,
  provisioning will fail. There is currently no way to select an alternate handle.
- **No automated credential migration.** Moving from the legacy backend to the portable backend
  requires re-registration at every relying party.

## Interoperability matrix

The following matrix tracks tested combinations of TPM implementations for portable credential
portability. A cell means: "a credential generated on TPM A can be loaded and used for signing
on TPM B, given both were provisioned from the same recovery seed."

| Source TPM | Target TPM | Status | Notes |
|---|---|---|---|
| swtpm | swtpm | **TESTED** | `tests/tpm_portable.rs` and `tests/tpm_portable_storage.rs` verify provision, generate, sign, load, seal, and unseal across two independent swtpm instances with the same seed. Wrong-seed TPM correctly fails. |
| Intel PTT (firmware TPM) | Intel PTT | Not yet tested | Same vendor, same firmware implementation. Expected to work; needs validation. |
| Intel PTT | AMD fTPM | Not yet tested | Cross-vendor. May surface differences in ECC key import, marshaling, or algorithm profile. |
| AMD fTPM | AMD fTPM | Not yet tested | Same vendor. Expected to work; needs validation. |
| Firmware TPM (PTT/fTPM) | Discrete TPM (e.g. Infineon, Nuvoton) | Not yet tested | Cross-implementation. Discrete TPMs may have different RSA/ECC key generation profiles. |
| Discrete TPM vendor A | Discrete TPM vendor B | Not yet tested | Highest risk of interoperability issues (different firmware, different algorithm profiles). |

Contributions of test results from hardware TPMs are welcome. Please open an issue or PR with
the TPM vendor, firmware version, and test outcome.
