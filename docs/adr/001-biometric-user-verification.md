# ADR 001: Biometric User Verification

## Status

Accepted

## Context

Passless currently uses desktop notifications for user verification (UV) in FIDO2 operations. This is a "something you have" factor (the device with passless running). To provide true multi-factor authentication, we need "something you are" - biometric verification.

Linux provides several options for biometric authentication:

1. **fprintd** - Standard Linux fingerprint daemon with D-Bus interface
2. **Webcam face recognition** - Using modern ML models via ONNX
3. **External commands** - Allow users to integrate any biometric tool

## Decision

We will implement a pluggable user verification system with multiple providers:

### Architecture

```
UserVerificationManager (chain of responsibility)
├── FprintdProvider (fingerprint via D-Bus)
├── FaceIdProvider (webcam + face recognition)
├── NotificationProvider (fallback, current behavior)
└── CommandProvider (user-defined script)
```

### Technology Choices

1. **D-Bus Integration**: Use `zbus` crate (pure Rust, async-native)
2. **Webcam Capture**: Use `nokhwa` crate (cross-platform, no OpenCV dependency)
3. **Face Recognition**: Use `face_id` crate (SCRFD detection + ArcFace embeddings via ONNX Runtime)
4. **Provider Selection**: Configurable chain with automatic fallback

### Configuration

```toml
[uv]
providers = ["fprintd", "face", "notification"]  # Try in order

[uv.fprintd]
timeout_seconds = 30

[uv.face]
enabled = true
camera_index = 0
threshold = 0.6
```

## Consequences

### Positive

- True biometric verification for FIDO2 operations
- Multiple provider options for different hardware
- Automatic fallback ensures users aren't locked out
- Modern Rust stack (zbus, face_id) with minimal C dependencies

### Negative

- Increased binary size and dependencies
- face_id downloads ONNX models from HuggingFace on first use
- Webcam access requires proper permissions
- fprintd requires system-level setup

### Neutral

- Face recognition provider is feature-gated (`--features face`) to reduce binary size
- Other providers (fprintd, notification, command) are always included
- Face embeddings stored locally in user's storage backend

## Implementation

1. Create `uv/` module with `UserVerificationProvider` trait
2. Implement provider chain in `UserVerificationManager`
3. Implement each provider (fprintd, face, notification, command)
4. Update authenticator to use manager instead of direct notifications

### Build Options

```bash
# Standard build (fprintd + notification providers)
cargo build

# With face recognition support (adds ~50MB+ due to ONNX Runtime)
cargo build --features face
```

## Alternatives Considered

1. **All providers feature-gated**: Rejected - fprintd and notification are lightweight enough to include by default
2. **Howdy integration**: Rejected - Python-based, command provider allows users to integrate it themselves
3. **OpenCV for face recognition**: Rejected - heavy C++ dependency, face_id uses ONNX Runtime instead
4. **PAM integration**: Rejected - indirect, requires PAM conversation setup

## References

- [fprintd D-Bus API](https://fprint.freedesktop.org/)
- [nokhwa crate](https://crates.io/crates/nokhwa)
- [face_id crate](https://crates.io/crates/face_id)
- [zbus crate](https://crates.io/crates/zbus)
