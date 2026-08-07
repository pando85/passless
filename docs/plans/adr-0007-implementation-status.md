# ADR 0007 implementation status

This document records implementation evidence separately from the normative ADR and verification matrix.

## Implemented in PR #402

- `same-user` and `isolated` identity modes share one daemon WebAuthn operation path.
- Mode selection resolves a complete credential backend handle: credential storage, PIN storage, key provider, namespace, and operation lock.
- Same-user operations use the existing human backend; isolated operations retain profile-owned storage and revocation.
- Autonomous agent evidence can satisfy UP and UV, including RP-required UV, without being recorded as human verification.
- Human confirmation or PIN/platform verification remains an explicit stricter policy and falls back to the native human ceremony path.
- `human_verification_prompt = "when-required"` omits a human prompt when the RP does not require UV; `always` preserves the stricter behavior.
- Authentication performs scoped multi-credential discovery and deterministic selection.
- Registration negotiates RP-requested algorithms and uses the selected backend provider.
- Dynamic credential scope lets a credential registered during a session authenticate immediately without relaunching the browser.
- Registration and authentication consume one shared replay set and operation budget for the bearer session.
- Browser requests propagate frame origin, top origin, cross-origin state, cancellation, timeout semantics, and the correct get/create Permissions Policy feature.
- Replayed identical operation requests are rejected and each short-lived session has a bounded operation budget.
- Portable-TPM backends propagate their real key provider instead of silently substituting software signing.

## Automated evidence

The branch is required to pass:

- Rustfmt and Clippy with all features and warnings denied.
- Build and unit tests on x86_64 and aarch64.
- Repository pre-commit checks.
- `make test-agent-validation`, the deterministic twelve-phase agent validation harness.

The final software-validation cycle is run from a normal maintainer-authored commit after all formatter, Clippy, deterministic-fixture, policy, and lifecycle corrections have landed. Bot-authored maintenance commits are not used as evidence when GitHub suppresses their pull-request workflows.

## External release evidence

The following remain environment-dependent release gates rather than claims made from ordinary GitHub-hosted CI:

- A real relying-party registration and authentication round trip using same-user credentials.
- A real relying-party isolated-mode regression round trip.
- Portable-TPM registration and authentication against a physical or recorded TPM laboratory environment.
- Independent review of the agent-as-user UV semantics and browser-extension trust boundary.

A required external gate that has not run must be reported as incomplete; it must not be represented as passing.
