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
        // 6. Daemon validates grant, generates keypair, writes credential
        // 7. Extension receives response and returns PublicKeyCredential to RP
        // 8. Verify credential appears in `passless agent admin grants` output
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
    fn test_e2e_registration_grant_expiry() {
        // E2E flow verifying grant expiry:
        // 1. Request a registration grant with a short TTL
        // 2. Wait for the grant to expire
        // 3. Attempt registration
        // 4. Verify the registration is rejected with a forbidden error
    }
}
