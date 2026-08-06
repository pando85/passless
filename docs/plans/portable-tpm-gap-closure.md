# Portable TPM gap-closure implementation plan

- **Status:** Complete (PR #354 merged). Phases 1–4 and 6 implemented; Phase 5 follow-ups tracked below.
- **Date:** 2026-07-23
- **Owners:** Passless maintainers
- **Covers:** [ADR 0003](../decisions/0003-portable-tpm-credential-keys.md); implements [issue #314](https://github.com/pando85/passless/issues/314)
- **Branch / PR:** `feat/portable-tpm-backend` → [PR #354](https://github.com/pando85/passless/pull/354)
- **Execution model:** Orchestrator delegates coding to subagents (**max 2 parallel**), validates each result, then commits.

## Purpose

Close every gap between ADR 0003 and the current implementation (PR #354). The portable TPM-resident
signing-key core is implemented and CI-green; what remains is the seed-provisioning UX change, the
one-time ES256 migration, and the security/correctness, portability, testing, and rollout items in
the ADR's "Remaining work" section.

The work is complete when every non-gated phase below is implemented, tested, lint-clean, and
committed to PR #354; every decision gate is resolved (documented decision) and implemented or
explicitly scoped out; and ADR 0003's "Implementation status" is updated accordingly.

## Execution ground rules

- The orchestrator does not write feature code directly; it delegates to subagents (max 2 in
  parallel) and validates results before committing. Independent tasks may run concurrently (up to
  2); dependent tasks run sequentially.
- Every code task ends with: `cargo fmt`, `cargo clippy --all-features --all-targets -- --deny warnings`,
  and the relevant `cargo test` targets. Pre-commit hooks (fmt, clippy, commitlint) must pass.
- Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, …).
- swtpm test hygiene: ALWAYS `pkill -x swtpm` before swtpm runs. NEVER `pkill -f swtpm` (kills the shell).
- All work lands on `feat/portable-tpm-backend` (PR #354).
- Decision gates (marked **DECISION GATE**) must be surfaced to the user and resolved before the
  gated implementation begins.

## Current state / key references

| Area | File | Notes |
|---|---|---|
| ADR | `docs/decisions/0003-portable-tpm-credential-keys.md` | Frozen format v1; migration + seed-UX decisions |
| Portable parent | `cmd/passless/src/storage/tpm/portable/parent.rs` | `PortableParent`, handle `0x81000001`, `FORMAT_VERSION 1`, `TPM2_Import` wrapper |
| Key provider | `cmd/passless/src/storage/tpm/portable/provider.rs` | `TpmCredentialKeyProvider`, ES256 (alg -7), `TPM2_Create`/`TPM2_Sign` |
| KDF | `cmd/passless/src/storage/tpm/portable/kdf.rs` | KDFa/KDFe/AES-128-CFB/HMAC |
| Storage adapter | `cmd/passless/src/storage/tpm/mod.rs` | `new_portable`; metadata AES-GCM seal at `:347` (no AAD) |
| CLI | `cmd/passless/src/commands/tpm.rs` | `provision`/`status`/`remove`; seed via `--generate`/`--seed-fd`/prompt |
| Config | `passless-core/src/config.rs` | `TpmAction`, `TpmBackendConfig.portable`, `BackendConfig::Tpm{portable}` |
| Authenticator | `cmd/passless/src/authenticator.rs` | `AuthenticatorService<S, P, K = SoftwareCredentialKeyProvider>` |
| PIN storage | `cmd/passless/src/pin_storage/tpm.rs` | `TpmPinStorage`, device-local primary (`:164-165`, `:202-203`) |
| Agent wiring | `cmd/passless/src/agent/storage_factory.rs:289`, `passless-core/src/agent/config.rs:266` | `portable: false` |
| Tests | `cmd/passless/tests/tpm_portable.rs`, `cmd/passless/tests/tpm_portable_storage.rs` | swtpm |
| Upstream | soft-fido2 v0.15.0 (`CredentialKeyProvider`) | repo at `/home/agil/passkeys/soft-fido2` |

Validation command set (reference):

```bash
cargo fmt --all --check
cargo clippy --all-features --all-targets -- --deny warnings
cargo test -p passless-rs --features tpm
cargo test -p passless-rs --features tpm --test tpm_portable --test tpm_portable_storage -- --test-threads=1
cargo build --features tpm
cargo build --features agent
pkill -x swtpm   # before swtpm test runs; NEVER 'pkill -f swtpm'
```

---

## Phase 1 — Seed provisioning UX ✅ (complete)

**Goal:** replace the non-intuitive `--seed-fd <N>` with `--seed-file <PATH>` and `--seed-stdin`,
keeping `--generate` and the default interactive prompt. (ADR 0003 → "Seed provisioning UX".)

### Tasks

**1.1 — Config (`passless-core/src/config.rs`).**
Change `TpmAction::Provision { generate, seed_fd: Option<i32>, path, tcti }` to
`{ generate: bool, seed_file: Option<PathBuf>, seed_stdin: bool, path: Option<String>, tcti: Option<String> }`.
Replace the `--seed-fd` clap arg with `--seed-file <PATH>` and `--seed-stdin`. Put `--generate`,
`--seed-file`, and `--seed-stdin` in a clap `ArgGroup` (mutually exclusive). Update help text.

**1.2 — CLI (`cmd/passless/src/commands/tpm.rs`).**
- Remove `read_hex_seed_from_fd`.
- Add `read_hex_seed_from_file(path) -> Result<Zeroizing<Vec<u8>>>`: read the file, take the first
  line, trim, `parse_hex_seed`. Before reading, inspect `std::fs::metadata(path)` permissions
  (`std::os::unix::fs::PermissionsExt`); if any group/other bit is set, `eprintln!` a warning
  recommending `chmod 600`.
- Add `read_hex_seed_from_stdin() -> Result<Zeroizing<Vec<u8>>>`: read stdin to a string, trim,
  `parse_hex_seed`.
- Update `provision(...)` signature and source selection order: `generate` → `seed_file` →
  `seed_stdin` → interactive `rpassword` prompt. Keep `parse_hex_seed` (exactly 32 bytes / 64 hex).
- Update the `dispatch` match arm for the new `Provision` fields.

**1.3 — Docs (`docs/TPM_PORTABLE.md`).** Replace `--seed-fd` examples with `--seed-file` and
`--seed-stdin` (e.g. `pass show fido2/seed | passless tpm provision --seed-stdin`).

**1.4 — Tests.** Unit tests for file and stdin seed parsing and the permission warning; confirm
`--generate` and prompt paths still work. If practical, an integration test provisioning via
`--seed-file` and via `--seed-stdin` against swtpm.

### Acceptance
- `passless tpm provision --seed-file seed.hex` works; warns when `seed.hex` is group/other-readable.
- `cat seed.hex | passless tpm provision --seed-stdin` works.
- `--generate` and interactive prompt unchanged.
- clap rejects combining `--generate`/`--seed-file`/`--seed-stdin`.
- `grep -rn seed_fd cmd/ passless-core/` returns nothing.

### Parallelization
1.1+1.2 are coupled → one subagent. After it lands, 1.3 (docs) + 1.4 (tests) can be a second
subagent.

---

## Phase 2 — `passless tpm migrate` (one-time ES256 import) ✅ (complete)

**Goal:** migrate legacy sealed-software ES256 credentials to the portable TPM-resident format,
preserving RP registrations (same credential ID + public key). (ADR 0003 → "Migration".)

**Runtime precondition:** portable parent provisioned (`passless tpm provision`).

**Note on ordering:** Phase 3.1 (metadata AAD binding) ideally lands before or alongside Phase 2 so
migrated records are cryptographically bound. The executor may pull 3.1 ahead of Phase 2 to avoid
rework; if Phase 2 lands first, retrofit 3.1 and re-run Phase 2 tests.

### Tasks

**2.1 — Import-existing-key capability.** Add a function to import an EXISTING P-256 private scalar
as a child signing key under the portable parent (location: `portable/provider.rs`, e.g.
`TpmCredentialKeyProvider::import_existing`, with a child-import helper in `portable/parent.rs`).
Reuse the existing `TPM2_Import` wrapper (ECDH/KDFe/KDFa/AES-128-CFB/HMAC), but:
- the sensitive area carries the **supplied** scalar (not TPM-generated);
- the child public template sets `sign | userWithAuth`, `fixedTPM`/`fixedParent` clear, ECDSA-SHA256,
  and **`sensitiveDataOrigin` CLEAR** (this is the critical difference from `generate()`, which uses
  `TPM2_Create` with `sensitiveDataOrigin` set).
Return the marshaled `TPM2B_PUBLIC` + `TPM2B_PRIVATE`. Verify the exact `tss-esapi` import API for a
keyed object with an externally supplied sensitive.

**2.2 — Public-key recomputation + verification.** Given the raw P-256 scalar, compute the public
point using the same ECDSA crate the software provider uses (inspect `soft-fido2` / current software
key path). Provide a helper to compare it against the legacy credential's stored COSE public key.

**2.3 — Config + CLI.** Add
`TpmAction::Migrate { credential_id: Option<String>, all: bool, dry_run: bool, backup_dir: Option<String>, path: Option<String>, tcti: Option<String> }`
to `passless-core/src/config.rs` with clap args (`--credential-id`, `--all`, `--dry-run`,
`--backup-dir`). Add the `dispatch` arm in `cmd/passless/src/commands/tpm.rs` → `migrate(...)`.

**2.4 — Migration logic** (new module, e.g. `cmd/passless/src/commands/tpm_migrate.rs`). For each
candidate legacy credential:
1. Require a provisioned portable parent; otherwise return an actionable error.
2. Skip credentials already in portable format (idempotent).
3. If algorithm ≠ ES256 (e.g. EdDSA): report as not-migratable and skip.
4. If `--dry-run`: report migratable/not-migratable only; change nothing.
5. Otherwise: unseal the legacy credential (legacy `TpmStorageAdapter`) → extract the raw scalar →
   recompute the public key and verify it matches the stored public key → `import_existing` under
   the portable parent → `TPM2_Load` + `TPM2_ReadPublic` → verify the TPM public key **exactly equals**
   the registered public key → run a local sign/verify self-test → build the portable record
   (carry over credential ID, RP ID/name, user, algorithm, `credProtect`, `cred_random`, creation
   time, discoverable flag; signing blobs = imported `TPM2B_PUBLIC`/`TPM2B_PRIVATE`; metadata sealed
   under the portable parent) → back up the legacy record to `--backup-dir` (default `.backup`
   subdir) → atomic-write the portable record → zeroize the scalar and all temp buffers.
6. Replace/remove the legacy record only after the self-test passes; keep the backup (rollback =
   restore backup).
7. Print a summary (migrated / skipped / failed counts).

**2.5 — Tests (swtpm)** — `cmd/passless/tests/tpm_migrate.rs`:
- Create a legacy sealed ES256 credential on swtpm A; provision the portable parent on swtpm A and B
  (same seed).
- `migrate --all`: assert a portable record exists, the legacy record is backed up, and the signing
  key is now TPM-resident.
- Assert a migrated assertion signature verifies against the **original** public key (RP registration
  preserved).
- Assert the migrated blob loads and signs on swtpm B (portability preserved).
- `--dry-run` changes nothing.
- An EdDSA legacy credential is reported not-migratable and left untouched (if constructible in test).
- Running `migrate` twice is idempotent (no duplication/corruption).

**2.6 — Docs (`docs/TPM_PORTABLE.md`).** Migration section: command usage; behavior; caveats (EdDSA
re-register; constant-zero counter; non-exportability guaranteed only from migration onward;
backup/rollback).

### Acceptance
Per ADR 0003 "Migration" plus all tests in 2.5 passing.

### Parallelization
2.1+2.2 are coupled → one subagent (sequential). 2.3+2.4 depend on 2.1 → same or next subagent.
After logic lands, 2.5 (tests) + 2.6 (docs) can be a second subagent.

---

## Phase 3 — Required security & correctness ✅ (complete)

Items 3.2–3.6 are largely independent → up to 2 parallel subagents. 3.1 is high-value and ideally
precedes/accompanies Phase 2. 3.7 is a **DECISION GATE**.

**3.1 — Metadata AAD binding (HIGH).** `cmd/passless/src/storage/tpm/mod.rs:347`. Add AAD over
`credential ID || RP ID || algorithm || provider version || TPM public blob` to the AES-GCM metadata
encryption on both seal and unseal paths; pass the AAD from the portable record write/read. Keep the
legacy path working (or version-gate it). *Test:* transplanting a metadata blob to a different
credential fails to authenticate/decrypt.

**3.2 — Persistent-handle collision detection.** `portable/parent.rs:224-240`. Before `evict_control`,
read the public area at `0x81000001`; if occupied by an object whose Name/template ≠ the expected
parent, refuse with an actionable error (never evict an unknown object). *Test:* occupy the handle
with a different object → `provision` refuses without evicting it.

**3.3 — TPM-clear / replacement actionable error.** `portable/parent.rs:144-152`. Introduce a distinct
error variant (e.g. `Error::TpmParentMismatch` / `TpmCleared`) instead of generic `Error::Other`, with
an actionable message (re-provision / wrong seed). *Test:* missing or wrong parent yields the specific
error, not "credential corrupt".

**3.4 — Downgrade protection.** `portable/provider.rs:287-289` + the record write path. Check the
record version before writing; refuse to overwrite a record with an unknown/newer version. *Test:*
a record stamped with version `N+1` is not overwritten by the current code.

**3.5 — Capability check.** `portable/provider.rs:249-251`. Query `TPM2_GetCapability` for ECC NIST
P-256, ECDSA-SHA256, and AES-128-CFB before registration; return an actionable error if unsupported
(replace the hardcoded `supports_algorithm` comparison). *Test:* the capability query runs and ES256
is reported supported on swtpm (full negative test optional — swtpm supports these).

**3.6 — Parameter-encrypted HMAC sessions.** `portable/parent.rs:216`, `portable/provider.rs:107`.
Use an HMAC session with AES-128-CFB parameter encryption for sensitive `TPM2_Import`/`TPM2_Create`
parameters (mirror the legacy seal path's session setup in `tpm/mod.rs:117-135`). *Test:* provisioning
and key creation still succeed with encrypted sessions enabled.

**3.7 — Parent/child authorization — DECISION GATE.** Surface to the user and document the decision
(ADR amendment or this plan): per-device local parent `authValue` (retaining the same Name/seed) vs.
explicitly documented empty-auth; independent child auth; whether `fixedParent` can be set on children;
interaction with Passless PIN/notification UV. Then implement the chosen model + tests. Until decided,
empty-auth remains acceptable for pre-1.0 but must be documented as a known limitation
(`parent.rs:506`, `provider.rs:108`, `provider.rs:313-314`).

---

## Phase 4 — Portability completeness ✅ (complete)

**4.1 — `cred_random` / PIN portability — DECISION GATE.** Decide: make `TpmPinStorage` portable
(seal PIN/`cred_random` state under the portable parent) OR document it as intentionally device-local.
- If portable: `cmd/passless/src/pin_storage/tpm.rs:164-165,202-203` — seal under the portable parent
  (`fixedTPM`/`fixedParent` clear). *Test:* PIN state provisioned on swtpm A unseals on swtpm B (same seed).
- If device-local: document explicitly in `docs/TPM_PORTABLE.md` and ADR 0003.

**4.2 — Agent-mode portable storage — DECISION GATE.** Decide: wire the portable adapter into agent
profiles OR explicitly scope it out.
- If wired: `cmd/passless/src/agent/storage_factory.rs:289` + `passless-core/src/agent/config.rs:266`
  — honor the `portable` flag. *Test:* an agent TPM profile uses the portable adapter.
- If scoped out: document in ADR 0003.

---

## Phase 5 — Testing & robustness (follow-ups)

The following items are **not done in PR #354** and are tracked as follow-ups:

**5.1 — Mock external provider test (soft-fido2).** Requires a separate soft-fido2 PR + release +
dependency bump in passless. Tracked as a follow-up.

**5.2 — Concurrency test.** Being implemented separately.

**5.3 — Transient-handle leak test.** Being implemented separately.

**5.4 — Power-loss / restart test.** Being implemented separately.

**5.5 — Fuzzing.** Requires `cargo-fuzz` target scaffolding. Tracked as a follow-up.

**5.6 — Cleared-TPM / occupied-handle error tests.** Covered by 3.2/3.3 implementation tests.

**5.7 — Hardware interoperability matrix.** Manual runs on Intel PTT / AMD fTPM / discrete TPMs;
not CI-runnable. Tracked as a follow-up.

---

## Phase 6 — Rollout ✅ (complete)

**6.1 — Mark the sealed format legacy.** Documentation updated with a deprecation notice directing
users to `passless tpm provision` + `passless tpm migrate`. Legacy support is retained (readable,
migratable); the legacy format is not removed.

---

## Suggested execution order

1. **Phase 1** (seed UX). — user-specified first.
2. **Phase 3.1** (metadata AAD) — recommended immediately before/within Phase 2 to avoid migrating
   unbound records (executor may reorder).
3. **Phase 2** (`tpm migrate`). — user-specified second.
4. **Phase 3.2–3.6** (independent; up to 2 parallel).
5. **Decision gates 3.7, 4.1, 4.2** — surface to the user; implement once decided.
6. **Phase 5** tests (up to 2 parallel as code lands); **5.1** may require a soft-fido2 PR.
7. **Phase 6** rollout.

## Definition of done

- All non-gated phases implemented, tested, `cargo fmt`/`clippy` clean, tests green, committed to PR #354. ✅
- Decision gates (3.7, 4.1, 4.2) resolved with documented decisions and implemented. ✅
- ADR 0003 updated to reflect completion. ✅
- PR #354 CI green (fmt, clippy, x86_64 + aarch64 build/test, agent validation). ✅
- Phase 5 testing follow-ups (5.1, 5.5, 5.7) tracked separately.
