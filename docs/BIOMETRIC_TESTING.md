# Biometric UV validation

The headless regression tests run in CI. **Physical fingerprint and webcam testing
cannot be automated on a normal GitHub-hosted runner**. Use this checklist on a
dedicated Linux workstation, with a disposable test account and temporary
credential store. Do not change an existing authenticator's production state.

## Automated tests: run before hardware tests

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --features tpm
cargo test -p passless-rs --features face --bin passless
make test-agent-validation
```

The `tpm` test requires `swtpm` and `libtss2-dev`. The `face` feature
requires native webcam dependencies; use the dependencies from
`.github/workflows/rust.yml` on Ubuntu.

## Physical fingerprint: fprintd

Prerequisites: a supported fingerprint reader and `fprintd` service,
an enrolled local login user, a working interactive desktop and
`/dev/uhid` access.

```bash
fprintd-enroll
fprintd-verify
cargo run -p passless-rs -- --uv-provider fprintd --backend-type local
```

Use a **disposable** WebAuthn/FIDO2 relying party or test site in a
separate browser profile. Request registration and authentication
with `userVerification: "required"`.

| Scenario | Expected outcome |
|---|---|
| Enrolled fingerprint succeeds | CTAP UV accepted only after physical scan |
| Unenrolled finger / mismatch | UV denied; no notification approval bypass |
| Swipe too short / off center | Reader permits retry until final status or timeout |
| User does not touch sensor | UV times out; operation fails |
| No enrolled prints | No UV success (enroll with `fprintd-enroll`) |
| Unplug reader during operation | Device error; no UV success |
| Stop/restart `fprintd` or plug reader after startup | Availability is rechecked, no stale cache |
| Unprivileged process emits a forged D-Bus signal | Signal is ignored unless sender owns `net.reactivated.Fprint` |
| Explicit notification provider with UV required | UV rejected; notification may still satisfy UP |
| PIN enforcement required | Existing PIN policy continues to take precedence |
| Agent delegated request | Existing operation lock and policy checks remain intact |

Record the OS, reader model, fprintd and libfprint versions, results,
and relevant redacted logs. Do not upload biometric templates or credentials.

## Physical webcam: experimental only

```bash
cargo run -p passless-rs --features face -- uv face-status
cargo run -p passless-rs --features face -- uv face-enroll --camera-index 0
cargo run -p passless-rs --features face -- uv face-verify --camera-index 0
```

Model download may happen on first use. Check model provenance first.
Verify all of these scenarios:

| Scenario | Expected outcome |
|---|---|
| No camera or camera permission denied | Clear failure, never UV acceptance |
| No enrolled face | Clear NotEnrolled failure |
| Enroll with five clear frames | Private template saved successfully |
| Same person | Local face matching reports acceptance |
| Another person | Local comparison denies |
| Two faces visible | Failure; it must not silently choose the first |
| Template truncated, malformed or containing NaN | Failure without panic |
| Template is a symlink or readable by group/other | Failure on Unix |
| Threshold is NaN, infinite, zero or greater than one | Configuration rejected |
| Static photo, video playback, synthetic face | **May match!** This is the known PAD/liveness limitation |
| WebAuthn with `userVerification: "required"` and face only | UV **must not be accepted** |

Never treat successful face matching as production-ready FIDO2 UV without
independently evaluated presentation-attack detection. A shared workstation
or malware with the user's permissions can access local templates.

## Custom verifier

Configure a dedicated, non-shell executable or script that actually
authenticates the user. Never use `true` as the configured verifier in
production. Validate the following manually:

- Exit 0 after a genuine verification: accepted.
- Exit non-zero: denied, no notification fallback for UV.
- Sleep beyond the configured timeout: operation ends with Timeout.
- Executable missing or permission denied: fail closed.
- Environment variables `PASSLESS_UV_OPERATION`, `PASSLESS_UV_RELYING_PARTY`,
  `PASSLESS_UV_USER` contain the documented request context.

A command verifier is trusted code and must enforce its own authentication
and any lockout policy. In `auto` mode the command provider is not selected.
