#[cfg(test)]
mod e2e_tests {
    #[test]
    #[ignore]
    fn test_e2e_registration_via_extension() {
        // E2E flow for registration via browser extension:
        // 1. Start daemon with agent profile:
        //    cargo run -- --agent --agent-profile <profile>
        // 2. Launch browser with extension pointing to daemon endpoint
        // 3. Navigate to a WebAuthn registration test page (e.g. webauthn.io)
        // 4. Trigger navigator.credentials.create() via the extension
        // 5. Extension sends POST /register to daemon sign server
        // 6. Daemon checks the lease-bound bearer and the exact-RP `register = "allow"` rule, generates
        //    the keypair, writes the credential
        // 7. Extension receives response and returns PublicKeyCredential to RP
        // 8. Verify the credential is in the profile's backend
    }

    #[test]
    #[ignore]
    fn test_e2e_registration_with_tpm() {
        // E2E flow for registration with TPM backend:
        // 1. Start swtpm or ensure hardware TPM is available
        // 2. Start daemon with TPM backend:
        //    cargo run -- --backend-type tpm --tpm-tcti "swtpm:path=$HOME/.local/run/swtpm-sock"
        // 3. Follow steps 2-7 from test_e2e_registration_via_extension
        // 4. Verify credential is sealed by TPM (file has .tpm extension)
        // 5. Restart daemon and verify credential can be used for authentication
    }

    #[test]
    #[ignore]
    fn test_e2e_registration_exclude_list() {
        // E2E flow verifying exclude list behavior:
        // 1. Register a credential for example.com
        // 2. Attempt re-registration with the credential ID in excludeCredentials
        // 3. Verify the registration is rejected with a conflict error
        // 4. Attempt re-registration without the credential in excludeCredentials
        // 5. Verify a new credential is created
    }

    #[test]
    #[ignore]
    fn test_e2e_registration_bearer_revoked_with_lease() {
        // E2E flow verifying that registration bearers die with the browser lease
        // (tests/agent-e2e E2E-11):
        // 1. Register with the live bearer
        // 2. Exit the browser (or revoke the lease)
        // 3. Attempt registration with the old bearer
        // 4. Verify the request is refused and an audited policy.deny(bearer_revoked) is recorded
    }
}
