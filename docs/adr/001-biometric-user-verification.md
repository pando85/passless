# ADR 001: Biometric user verification

## Status

Accepted for fingerprint verification. Webcam matching remains **experimental** and
MUST NOT satisfy FIDO2/CTAP user verification until independently validated
presentation-attack detection (liveness) is integrated.

## Problem and trust boundary

A notification proves **user presence (UP)**, not user identity. It must never
set or satisfy a FIDO2 **user verification (UV)** result. A camera embedding
comparison alone is vulnerable to photos, replays and synthetic media.

## Decision

The authenticator uses a pluggable verification manager:

- `fprintd`: OS-managed enrolled fingerprint via the system D-Bus service.
  Can satisfy UV only after successful fingerprint verification.
- `notification`: desktop confirmation, **UP only**. It may be used as
  the presence fallback when a fingerprint reader is absent or unavailable.
- `command`: custom verifier, explicitly enabled and selected by an
  administrator. Exit 0 means accepted; nonzero means denied; timeout fails
  closed. Commands run without a shell unless one is explicitly configured.
  A trivial success command must never be configured for production UV.
- `face`: webcam and face-embedding comparison, **experimental**. Enrollment,
  storage and local matching tests are supported. A face match is *not* strong
  FIDO2 UV because this implementation has no liveness detection.

There is one configured provider selection, not an ordered list. With
`provider = "auto"`, fingerprint is attempted first, then desktop notification
for **UP only**. For UV, the manager excludes notifications and experimental
face recognition; if no eligible provider is available it denies UV.

An explicit denial stops the provider chain. Failures or timeouts can fall
back only to another provider with adequate assurance.

## Configuration

```toml
[uv]
provider = "auto" # auto | fprintd | face | notification | command
timeout_seconds = 30

[uv.fprintd]
enabled = true

[uv.face]
enabled = false
camera_index = 0
threshold = 0.6

[uv.command]
enabled = false
command = []
```

`threshold` must be finite, greater than 0 and at most 1. For a dedicated
fingerprint-only authenticator, set `provider = "fprintd"`. A command provider
requires `provider = "command"`, `enabled = true`, and a nonempty
`command` array. Command execution is limited by the verification timeout.

The older `security.notification_timeout` is distinct from
`uv.timeout_seconds`. The UV manager uses the latter.

## Face enrollment and local smoke testing

Build with `cargo build -p passless-rs --features face`. Then run:

```bash
passless uv face-status
passless uv face-enroll --camera-index 0 --threshold 0.6
passless uv face-verify --camera-index 0 --threshold 0.6
```

Five face samples are averaged. An error is returned when a frame contains
more than one detected face. Templates are stored under the user's
`XDG_DATA_HOME/passless/face_embeddings/face_template.bin`, with a private
directory and 0600 file permissions on Unix. Templates are still **not
cryptographically encrypted**; file permissions do not protect against
malware running as the same account. A known-good biometric template must not
be treated as an MFA or liveness guarantee.

The analyzer may download model files on first use, so an initial network
connection is needed. Users must review the privacy and provenance of the
models before enrollment.

## Tests and acceptance

CI exercises default and TPM-enabled builds, headless face compilation and
unit tests, command timeout behavior, invalid face templates and strict
UV/UP separation. CI cannot validate camera liveness, OS biometrics or
fingerprint hardware.

Follow `docs/BIOMETRIC_TESTING.md` for the local device-validation matrix.

## Follow-up required for production face UV

Introduce an audited liveness/PAD implementation (or a trusted
platform biometric API), validate demographic and environmental performance,
spoof/replay resistance, privacy, model delivery and retention, then define
a calibrated threshold and enable `supports_strong_uv` only after those
acceptance tests pass. No source-code-only assertion can replace this review.

## References

- [fprintd D-Bus Device API](https://fprint.freedesktop.org/fprintd-dev/Device.html)
- [FIDO user presence and verification requirements](https://fidoalliance.org/specifications/)
- [nokhwa](https://crates.io/crates/nokhwa)
- [face_id](https://crates.io/crates/face_id)
