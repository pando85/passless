# Agent passkey registration testing

> **EXPERIMENTAL.** Agent registration is implemented but not yet validated for production use.

How registration ([Agent passkey registration](AGENT_REGISTRATION.md)) is tested. All paths use the
daemon's Unix-socket transport; there is no HTTP `/register` endpoint to call by hand.

## Unit tests

```bash
cargo test --all-features -p passless-rs --bin passless agent::register::tests
cargo test --all-features -p passless-rs --bin passless agent::sign::tests::registration_lease_tests
```

`agent::register::tests` cover origin and RP verification (`test_register_origin_verification`,
`test_register_origin_spoofing_prevented`), the rule (`test_register_rejects_denied_policy`,
`test_register_under_wildcard_is_always_denied`, `test_register_allow_needs_no_enrollment_grant`),
credential storage and the response (`test_register_writes_credential`,
`test_register_success_response_fields`), `excludeCredentials` (`test_register_exclude_list_match`) and
serialization of concurrent requests (`test_register_concurrent_requests_serialized`). Registration
bearers are bound to the browser lease and revoked with it:
`sign::tests::registration_lease_tests`.

## End-to-end scenarios

The hermetic harness in `tests/agent-e2e` runs a real Chromium, a notification server double, a test
RP that verifies the attestation, and the daemon, with no public site:

| Scenario | Asserts |
|---|---|
| E2E-02 | Isolated `allow`: register then authenticate; the credential lands in the profile's store, not yours |
| E2E-11 | A registration with the bearer of an exited browser is refused and audited |
| E2E-27 | `register = "request"` approved: one registration, `authenticate = allow` persisted with `kind=registration`, the next registration prompts again |
| E2E-51 | `create()` from an unfocused tab: the page gets `NotAllowedError`, the audit shows the registration, deleting the orphan credential cleans up |

See `tests/agent-e2e/README.md` to run them (`make test-agent-e2e`, `make test-agent-e2e-full`). They
start browsers and a private D-Bus; the deterministic `make test-agent-validation` does not.

## Manual check

1. Configure an exact rule with `register = "allow"` ([Agent registration](AGENT_REGISTRATION.md)),
   restart the daemon and check `passless doctor --agents`.
2. Start a browser through an MCP adapter or `passless agent browser`
   ([Browser tools](agents/browser-tools.md)) and register at a test RP such as `webauthn.io`, with the
   page in the foreground.
3. Verify:
   - the daemon wrote a credential (`passless agent-admin credential list --domain <rp>`);
   - the audit holds a reservation and a terminal record
     (`passless agent-admin audit export --format json`, `passless agent-admin audit verify`);
   - `clientDataJSON` has type `webauthn.create`, the attestation format is `none`, and the
     authenticator data carries the Passless AAGUID (`6669646F2E706173736C6573732E7273`).

Origin checks that must be refused for `rp_id = "example.com"`: `http://example.com`,
`https://example.com:8443`, any path, query or fragment, `https://notexample.com` and
`https://example.com.evil.com`.
