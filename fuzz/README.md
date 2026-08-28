# Agent protocol fuzzing

This directory contains the first fuzzing targets for the Passless agent security boundary.

The initial scope is intentionally narrow and pure-Rust:

- `agent_protocol_decode` exercises the bounded seqpacket JSON codec, request-frame deserialization,
  request validation, and validated frame round-tripping.
- `agent_request_validation` feeds arbitrary JSON into admin requests, principal requests, and
  browser registration requests, then exercises their validation and validated round-tripping.

The security objective is broader than crash resistance: accepted input must have one stable
interpretation across decode, validation, serialization, and decode again.

## Prerequisites

Install the nightly toolchain and `cargo-fuzz`:

```console
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

## Run locally

From the repository root:

```console
cargo +nightly fuzz run agent_protocol_decode -- -max_total_time=60
cargo +nightly fuzz run agent_request_validation -- -max_total_time=60
```

Or run the bounded smoke campaign used by CI:

```console
make test-agent-fuzz-smoke
```

Corpus seeds under `fuzz/corpus/` are committed intentionally. Add minimized reproductions for
security-sensitive bugs so future campaigns retain historical coverage.

Crashing inputs are written under `fuzz/artifacts/` and are ignored by Git. A discovered bug should
be reduced, converted into a deterministic regression test where practical, and tracked separately
instead of weakening the fuzz assertion.

## Current boundary and follow-up work

This is the first tranche of issue #458. It does **not** yet cover the complete agent trust surface.
Follow-up targets should exercise:

- browser-derived origin/top-origin and RP relationship validation;
- native-messaging framing at the extension/sign-proxy boundary;
- one-shot intent/session/replay state machines;
- credential-selection ambiguity and namespace isolation;
- audit reservation fault injection before key use.

Those targets should remain narrow rather than growing one end-to-end fuzzer with a large,
non-deterministic environment.
