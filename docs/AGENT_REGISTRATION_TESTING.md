# Agent Passkey Registration Testing Guide

## Overview

This document covers testing the agent-driven passkey registration feature (ADR 0006). The feature allows agents to register passkeys without human interaction via the daemon's `/register` HTTP endpoint and a browser extension that overrides `navigator.credentials.create()`.

**What this document covers:**
- Manual testing with webauthn.io
- Automated unit and integration test execution
- Security verification of the registration pipeline
- Troubleshooting common failures

**Prerequisites:**
- Passless built with `--features agent`
- A webauthn.io account (free)
- A browser with extension loading support (Chromium-based)

## Quick Start

```bash
# Build with agent support
cargo build --features agent

# Run unit tests for the registration handler
cargo test --features agent -- register::tests --nocapture

# Run the full agent test suite
cargo test --features agent -- agent:: --nocapture
```

## Manual Testing with webauthn.io

### Step 1: Set up test environment

```bash
rm -rf /tmp/passless-webauthn-test
mkdir -p /tmp/passless-webauthn-test/fido2
mkdir -p /tmp/passless-webauthn-test/agent-credentials
mkdir -p /tmp/passless-webauthn-test/audit

cat > /tmp/passless-webauthn-test/config.toml << 'EOF'
[agents]
enabled = true
audit_path = "/tmp/passless-webauthn-test/audit"

[agents.profiles.webauthn-test]
mode = "isolated"
principal_user = "testuser"
registration_allowed = true

[[agents.profiles.webauthn-test.rules]]
rp_id = "webauthn.io"
register = { authorization = "allow", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "none", user_verification = "none" }

[agents.profiles.webauthn-test.device]
name = "passless-agent-webauthn"
phys = "webauthn-test-phys"
uniq = "webauthn-test-uniq"
vendor_id = 4660
product_id = 22137

[agents.profiles.webauthn-test.storage.local]
path = "/tmp/passless-webauthn-test/agent-credentials"
pin_path = "/tmp/passless-webauthn-test/agent-pin"

[local]
path = "/tmp/passless-webauthn-test/fido2"
EOF
```

### Step 2: Start the daemon

```bash
rm -rf /run/user/$(id -u)/passless /run/user/$(id -u)/agent

cargo run --features agent -- \
  --config-path /tmp/passless-webauthn-test/config.toml \
  --backend-type local \
  --local-path /tmp/passless-webauthn-test/fido2 \
  --always-uv=false 2>&1 | tee /tmp/passless-webauthn-test/daemon.log &

sleep 3
grep "Sign HTTP server listening" /tmp/passless-webauthn-test/daemon.log
```

Expected output:
```
INFO Sign HTTP server listening on 127.0.0.1:<port>
```

Note the port number for later use.

### Step 3: Launch browser with extension

```bash
passless agent-admin browser launch --profile webauthn-test --url https://webauthn.io/
```

This command:
- Generates a bearer token for the session
- Requests registration grants for all allowed RP IDs
- Registers registration and sign contexts
- Launches Chromium with the agent extension loaded

Expected output:
```json
{
  "lease_id": "abc123...",
  "profile_id": "webauthn-test",
  "pid": 12345,
  "start_url": "https://webauthn.io/"
}
```

### Step 4: Register on webauthn.io

1. The browser is already open at https://webauthn.io/
2. Enter username `passless-agent-test`
3. Click **Register**
4. The extension intercepts `navigator.credentials.create()` and forwards to the daemon

### Step 5: Verify the result

```bash
# Check daemon logs for registration events
grep -i "register" /tmp/passless-webauthn-test/daemon.log

# Check audit log
ls /tmp/passless-webauthn-test/audit/

# Check credential storage
ls /tmp/passless-webauthn-test/agent-credentials/

# Verify via admin CLI
passless agent-admin credential list --rp-id webauthn.io
```

Expected: a new credential appears in storage and the audit log records a `Register` action.

## Automated Testing

### Unit tests

The registration handler has comprehensive unit tests in `cmd/passless/src/agent/register.rs`:

```bash
# All registration handler tests
cargo test --features agent -- register::tests

# Specific test categories
cargo test --features agent -- register::tests::test_register_origin_verification
cargo test --features agent -- register::tests::test_register_rejects_expired_grant
cargo test --features agent -- register::tests::test_register_rejects_denied_policy
cargo test --features agent -- register::tests::test_register_origin_spoofing_prevented
cargo test --features agent -- register::tests::test_register_writes_credential
cargo test --features agent -- register::tests::test_register_success_response_fields
cargo test --features agent -- register::tests::test_register_concurrent_requests_serialized
```

### Policy engine tests

```bash
# Registration authorization tests
cargo test --features agent -- policy_engine::tests::test_authorize_registration
```

### Grant system tests

```bash
# Registration grant lifecycle tests
cargo test --features agent -- grant::tests::test_registration
```

### Full agent test suite

```bash
cargo test --features agent -- agent:: --nocapture
```

## Verification Checklist

- [ ] Daemon starts without errors
- [ ] HTTP server binds to a port (check log for `Sign HTTP server listening`)
- [ ] `browser launch` creates registration grants and contexts
- [ ] `/register` endpoint accepts POST requests with bearer token
- [ ] Credential is stored in the backend (check storage directory)
- [ ] `clientDataJSON` contains `"type":"webauthn.create"`
- [ ] `authenticatorData` contains the passless AAGUID (`6669646F2E706173736C6573732E7273`)
- [ ] Attestation object uses format `"none"` (self-attestation)
- [ ] Audit log records the `Register` action
- [ ] Extension intercepts `credentials.create()` without showing native modal
- [ ] webauthn.io shows success after registration

## Security Verification

### Origin validation

Test that the daemon rejects requests with invalid origins:

```bash
# The handler rejects these origins for rp_id "example.com":
# - http://example.com          (not HTTPS)
# - https://example.com:8443    (port not allowed)
# - https://example.com/path    (path not allowed)
# - https://example.com?foo=bar (query not allowed)
# - https://example.com#frag    (fragment not allowed)
# - https://notexample.com      (host mismatch)
# - https://example.com.evil.com (suffix mismatch)
```

Verified by unit test: `test_register_origin_spoofing_prevented`

### Grant expiry

```bash
# Request a grant with 5-second TTL
passless agent-admin delegation request-registration \
  --profile webauthn-test \
  --rp webauthn.io \
  --session-ttl 5

# Wait for expiry
sleep 6

# Attempt registration - should fail with "registration grant not active"
```

Verified by unit test: `test_register_rejects_expired_grant`

### Policy enforcement

Create a config with registration denied:

```toml
[[agents.profiles.deny-test.rules]]
rp_id = "example.com"
register = { authorization = "deny", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "none", user_verification = "none" }
```

Attempt registration - should fail with `ErrorCode::Forbidden` and audit reason `ActionNotAllowed`.

Verified by unit test: `test_register_rejects_denied_policy`

### Exclude list

When a relying party sends `excludeCredentials` matching an existing credential, the daemon returns `ErrorCode::Conflict`.

Verified by unit test: `test_register_exclude_list_match`

### Audit trail

```bash
# Check audit log entries
passless agent-admin audit status

# Verify integrity
passless agent-admin audit verify

# Export for inspection
passless agent-admin audit export --format json
```

Every registration attempt (allowed or denied) produces an audit event with:
- Profile ID
- Action (`Register`)
- RP ID
- Outcome (allow/deny)
- Deny reason (if denied)
- Timestamp

## Troubleshooting

### "Agent subsystem failed to start"

**Cause:** Stale runtime directories from a previous instance.

```bash
rm -rf /run/user/$(id -u)/passless /run/user/$(id -u)/agent
```

### "missing_authorization" on `/register`

**Cause:** Request sent without a bearer token.

The extension must include `Authorization: Bearer <token>` in the HTTP request. The token is bound to the registration grant during session setup.

### "policy_denied" / `ErrorCode::Forbidden`

**Cause:** The agent profile's RP rule does not allow registration.

Verify the config:
```toml
[[agents.profiles.<name>.rules]]
rp_id = "webauthn.io"
register = { authorization = "allow", ... }
```

Also check `registration_allowed = true` is set on the profile.

### "grant_not_found" / "registration grant not active"

**Cause:** The registration grant expired or was never created.

1. Request a new grant: `passless agent-admin delegation request-registration`
2. Check the TTL is sufficient for your test
3. Verify the grant ID in the request context matches

### "credential matches exclude list"

**Cause:** The relying party sent an `excludeCredentials` entry matching an existing credential.

This is correct WebAuthn behavior - the RP already has a credential for this user. Delete the existing credential or use a different user.

### Extension not intercepting `credentials.create()`

**Cause:** The extension is not loaded or not active on the page.

1. Verify the browser was launched with `--load-extension=<path>`
2. Check browser console for extension errors
3. Verify the page origin matches an RP rule in the profile

### Key generation failed

**Cause:** For TPM backend, the TPM is not accessible. For software backend, check daemon logs.

```bash
# Check daemon logs
tail -50 /tmp/passless-webauthn-test/daemon.log
```

## Related Documentation

- [ADR 0006: Agent Passkey Registration](decisions/0006-agent-passkey-registration.md)
- [Agent Registration Guide](AGENT_REGISTRATION.md)
- [ADR 0005: Delegated Autonomous Authentication](decisions/0005-delegated-autonomous-authentication-redesign.md)
