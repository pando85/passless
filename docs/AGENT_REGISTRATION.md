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

### Step 2: Request Registration Grant

From your agent process, request a registration grant via IPC:

```rust
use passless_core::agent::{AdminRequest, AdminResponse};

let request = AdminRequest::RequestRegistration {
    profile_id: "ci-agent".into(),
    rp_id: "gitea.example.com".into(),
    max_session_ttl: 300,
    reason: Some("CI/CD setup".into()),
};

let response = agent_client.send(request).await?;

let grant_id = match response {
    AdminResponse::RegistrationGranted { registration_grant_id } => registration_grant_id,
    _ => return Err("Registration denied".into()),
};
```

### Step 3: Navigate to Registration Page

Launch the browser with the extension and navigate to the RP's registration page:

```rust
let browser = launch_browser_with_extension(&grant_id)?;
browser.navigate("https://gitea.example.com/register").await?;
```

### Step 4: Trigger Registration

The extension automatically intercepts `navigator.credentials.create()` and handles the registration flow. No additional code is needed on the agent side.

### Step 5: Use the Credential

After registration, the credential is stored and can be used for authentication:

```rust
let auth_request = AdminRequest::RequestDelegation {
    profile_id: "ci-agent".into(),
    rp_id: "gitea.example.com".into(),
    credential_ref: new_credential_ref,
    max_session_ttl: 300,
    reason: Some("CI/CD authentication".into()),
};
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

```rust
let grant = request_registration_grant("ci-agent", "gitea.example.com", 300).await?;

let browser = launch_browser(grant).await?;
browser.navigate("https://gitea.example.com/user/sign_up").await?;

browser.fill_field("username", "ci-bot").await?;
browser.fill_field("email", "ci-bot@example.com").await?;
browser.click("Register").await?;

// Extension handles passkey registration automatically
// Credential is now available for authentication
```

### Example 2: Credential Rotation

```rust
let grant = request_registration_grant("ci-agent", "gitea.example.com", 300).await?;

let browser = launch_browser(grant).await?;
browser.navigate("https://gitea.example.com/user/settings/security").await?;

browser.click("Add Passkey").await?;

// Extension handles registration
// Old credential can be revoked if needed
```

## Related Documentation

- [ADR 0006: Agent Passkey Registration](decisions/0006-agent-passkey-registration.md)
- [ADR 0005: Delegated Autonomous Authentication](decisions/0005-delegated-autonomous-authentication-redesign.md)
- [Grant Mechanism & Authentication Flows](plans/adr-0005-grant-mechanism.md)
