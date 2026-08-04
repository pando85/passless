# Agent Passkey Registration Guide

This guide explains how to configure and use agent-driven passkey registration.

## Overview

Agent registration allows automated processes to create passkeys without human interaction. This is useful for:
- Initial setup of CI/CD pipelines
- Credential rotation
- Provisioning credentials on new services

## Prerequisites

- Passless daemon running with agent support
- Browser extension loaded (via `--load-extension`)
- Agent profile configured with registration permissions

## Configuration

### Step 1: Define Agent Profile

Create or update your agent profile in `~/.config/passless/config.toml`:

```toml
[profiles.ci-agent]
max_session_ttl = 3600
registration_allowed = true

[[profiles.ci-agent.rules]]
rp_id = "gitea.example.com"
register = { authorization = "allow", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "none", user_verification = "none" }
```

**Key fields:**
- `registration_allowed`: Global flag to enable registration for this profile
- `rules[].register.authorization`: Per-RP registration permission (allow/deny)
- `rules[].register.user_presence`: UP requirement (none/human)
- `rules[].register.user_verification`: UV requirement (none/human)

### Step 2: Launch Browser with Extension

The `browser launch` command automatically requests registration grants for all allowed RP IDs in the profile:

```bash
passless agent-admin browser launch --profile ci-agent --url https://gitea.example.com/register
```

This command:
- Generates a bearer token for the session
- Requests registration grants for all allowed RP IDs
- Registers registration and sign contexts with the daemon
- Launches Chromium with the agent extension loaded

**Output:**
```json
{
  "lease_id": "abc123...",
  "profile_id": "ci-agent",
  "pid": 12345,
  "start_url": "https://gitea.example.com/register"
}
```

### Step 3: Trigger Registration

The extension automatically intercepts `navigator.credentials.create()` and handles the registration flow. No additional code is needed on the agent side.

### Step 4: Use the Credential

After registration, the credential is stored and can be used for authentication. The same browser session can be used for authentication, or you can launch a new session:

```bash
# Launch a new browser session for authentication
passless agent-admin browser launch --profile ci-agent --url https://gitea.example.com/login

# The extension intercepts navigator.credentials.get() and handles authentication
```

## Security Considerations

### Default Deny

Registration is **denied by default**. You must explicitly enable it:
1. Set `registration_allowed = true` in the profile
2. Set `register.authorization = "allow"` for each RP

### Audit Trail

All registration operations are audited:
- Grant request (profile, RP ID, timestamp)
- Grant approval/denial
- Registration attempt (origin, RP ID, credential ID)
- Registration success/failure

### Key Generation

- **Software backend**: Keys are generated in the daemon and stored in the credential file
- **TPM backend**: Keys are generated and sealed by the TPM; the private key never leaves the TPM

### Grant Lifecycle

Registration grants are:
- **Time-bounded**: Expire after `max_session_ttl` seconds
- **RP-scoped**: Only valid for the specified RP ID
- **One-time use**: Consumed after successful registration

## Troubleshooting

### Registration Denied

**Symptom:** Registration fails with "PolicyDenied" error

**Solution:**
1. Check that `registration_allowed = true` in the profile
2. Check that `register.authorization = "allow"` for the RP
3. Verify the RP ID matches exactly (case-sensitive)

### Grant Not Found

**Symptom:** Registration fails with "GrantNotFound" error

**Solution:**
1. Ensure you requested a registration grant before navigating to the RP
2. Check that the grant hasn't expired (TTL)
3. Verify the grant ID is correct

### Origin Mismatch

**Symptom:** Registration fails with "InvalidOrigin" error

**Solution:**
1. Ensure the RP page is served over HTTPS
2. Check that the origin matches the RP ID
3. Verify there are no redirects that change the origin

### Key Generation Failed

**Symptom:** Registration fails with "KeyGenerationFailed" error

**Solution:**
1. For TPM backend: Check that the TPM is accessible
2. For software backend: Check that the key provider is configured
3. Check daemon logs for detailed error messages

## Examples

### Example 1: CI/CD Pipeline Setup

```bash
# Launch browser with extension
passless agent-admin browser launch --profile ci-agent --url https://gitea.example.com/user/sign_up

# The extension intercepts navigator.credentials.create() when the page triggers it
# Credential is now available for authentication
```

### Example 2: Credential Rotation

```bash
# Launch browser with extension
passless agent-admin browser launch --profile ci-agent --url https://gitea.example.com/user/settings/security

# Click "Add Passkey" on the page
# Extension handles registration automatically
# Old credential can be revoked if needed
```

## Related Documentation

- [ADR 0006: Agent Passkey Registration](decisions/0006-agent-passkey-registration.md)
- [ADR 0005: Delegated Autonomous Authentication](decisions/0005-delegated-autonomous-authentication-redesign.md)
- [Grant Mechanism & Authentication Flows](plans/adr-0005-grant-mechanism.md)
