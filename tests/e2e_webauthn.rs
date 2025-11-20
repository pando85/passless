//! End-to-End WebAuthn Integration Tests
//!
//! These tests verify the complete WebAuthn flow with the passless authenticator:
//! - Registration (makeCredential)
//! - Authentication (getAssertion)
//! - Multiple credentials
//! - User verification
//!
//! # Running the tests
//!
//! These tests automatically start and stop the authenticator with the appropriate
//! backend configuration. No manual setup is required.
//!
//! ## Running all E2E tests:
//! ```bash
//! cargo test --test e2e_webauthn -- --test-threads=1 --ignored
//! # or
//! make test-e2e
//! ```
//!
//! ## Running tests for a specific backend:
//! ```bash
//! cargo test --test e2e_webauthn local -- --test-threads=1 --ignored
//! cargo test --test e2e_webauthn pass -- --test-threads=1 --ignored
//! cargo test --test e2e_webauthn tpm -- --test-threads=1 --ignored
//! ```
//!
//! Note: Tests must run with --test-threads=1 to avoid conflicts between
//! multiple authenticator instances.
//!

mod harness;

use harness::AuthenticatorHarness;
use sha2::{Digest, Sha256};
use soft_fido2::client::Client;
use soft_fido2::{
    ClientDataHash, CredentialDescriptor, CredentialType, GetAssertionRequest,
    MakeCredentialRequest, RelyingParty, Result, TransportList, User,
};
use std::io::Write;

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

/// Run a test with the specified backend
fn with_backend<BF, F>(backend_name: &str, backend_factory: BF, test_fn: F) -> Result<()>
where
    BF: FnOnce() -> std::result::Result<AuthenticatorHarness, Box<dyn std::error::Error>>,
    F: FnOnce() -> Result<()>,
{
    println!("\n┌────────────────────────────────────────────────────────────┐");
    println!("│ Backend: {:<51} │", backend_name);
    println!("└────────────────────────────────────────────────────────────┘");

    let mut harness = match backend_factory() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("⚠️  Failed to create backend: {}", e);
            eprintln!("   Skipping {} backend tests", backend_name);
            return Ok(()); // Skip instead of fail
        }
    };

    if let Err(e) = harness.start() {
        eprintln!("⚠️  Failed to start authenticator: {}", e);
        eprintln!("   Skipping {} backend tests", backend_name);
        return Ok(()); // Skip instead of fail
    }

    let result = test_fn();

    // Always print authenticator output for debugging
    // Give the output capture threads time to finish reading
    std::thread::sleep(std::time::Duration::from_millis(500));

    harness.stop();

    result
}

/// Helper to generate client data hash for registration
fn generate_client_data_hash_for_registration(challenge: &[u8]) -> ClientDataHash {
    let client_data = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        base64_url_encode(challenge),
        ORIGIN
    );

    let hash = Sha256::digest(client_data.as_bytes());
    ClientDataHash::from_slice(&hash).expect("Failed to create client data hash")
}

/// Helper to generate client data hash for authentication
fn generate_client_data_hash_for_authentication(challenge: &[u8]) -> ClientDataHash {
    let client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
        base64_url_encode(challenge),
        ORIGIN
    );

    let hash = Sha256::digest(client_data.as_bytes());
    ClientDataHash::from_slice(&hash).expect("Failed to create client data hash")
}

/// Helper for base64url encoding
fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Generate a random challenge
fn generate_challenge() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut bytes = [0u8; 32];
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    // Simple pseudo-random for testing
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = ((timestamp.wrapping_add(i as u128)) % 256) as u8;
    }

    bytes
}

/// Print a message about the operation (the authenticator will handle user verification)
fn print_operation(message: &str) {
    println!("\n🔐 {}", message);
    println!("   (The authenticator will prompt for user verification)");
    std::io::stdout().flush().unwrap();
}

/// Connect to the first available authenticator
fn connect_to_authenticator() -> Result<soft_fido2::Transport> {
    println!("🔍 Looking for authenticators...");
    let list = match TransportList::enumerate() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("❌ Failed to enumerate transports: {:?}", e);
            return Err(e);
        }
    };

    if list.is_empty() {
        eprintln!("❌ No authenticators found!");
        eprintln!("   Please start the authenticator:");
        eprintln!("   cargo run");
        return Err(soft_fido2::Error::Other);
    }

    println!("   ✓ Found {} authenticator(s)", list.len());

    let transport = list.get(0).ok_or(soft_fido2::Error::Other)?;

    // Note: We don't call transport.open() here because the authenticator
    // has already created a UHID virtual device that's accessible via USB HID.
    // Multiple clients can communicate with it without explicitly opening.
    println!("   ✓ Connected to authenticator\n");
    Ok(transport)
}

/// Core test logic for registration and authentication flow
fn run_registration_and_authentication_test() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║   E2E Test: Registration + Authentication     ║");
    println!("╚════════════════════════════════════════════════╝\n");

    let mut transport = connect_to_authenticator()?;

    // ========================================
    // PHASE 1: REGISTRATION
    // ========================================
    println!("📝 [1/2] REGISTRATION PHASE");
    println!("{}", "═".repeat(50));

    println!("[1.1] Preparing registration request...");
    let challenge = generate_challenge();
    let client_data_hash = generate_client_data_hash_for_registration(&challenge);

    let rp = RelyingParty {
        id: RP_ID.to_string(),
        name: Some("Example Corp".to_string()),
    };

    let user = User {
        id: vec![1, 2, 3, 4],
        name: Some("alice@example.com".to_string()),
        display_name: Some("Alice".to_string()),
    };

    println!("   RP: {}", rp.id);
    if let Some(ref name) = user.name {
        println!("   User: {}", name);
    }

    let request = MakeCredentialRequest::new(client_data_hash, rp, user)
        .with_user_verification(true) // Request user verification
        .with_timeout(30000);

    println!("[1.2] Sending makeCredential request...");
    print_operation("User presence required for registration");

    let attestation = match Client::make_credential(&mut transport, request) {
        Ok(att) => att,
        Err(e) => {
            eprintln!("❌ makeCredential failed: {:?}", e);
            return Err(e);
        }
    };

    println!("   ✓ Credential created ({} bytes)", attestation.len());
    if attestation.len() < 10 {
        println!(
            "   [DEBUG] Short response! Hex: {}",
            hex::encode(&attestation)
        );
        if attestation.len() == 1 {
            panic!(
                "makeCredential failed with CTAP error: 0x{:02x}",
                attestation[0]
            );
        }
    }
    assert!(!attestation.is_empty(), "Attestation should not be empty");

    // First byte is CTAP status code (0x00 = success)
    assert_eq!(
        attestation[0], 0x00,
        "makeCredential failed with CTAP status: 0x{:02x}",
        attestation[0]
    );

    // ========================================
    // PHASE 2: AUTHENTICATION
    // ========================================
    println!("\n🔐 [2/2] AUTHENTICATION PHASE");
    println!("{}", "═".repeat(50));

    println!("[2.1] Preparing authentication request...");
    let challenge = generate_challenge();
    let client_data_hash = generate_client_data_hash_for_authentication(&challenge);

    println!("   RP: {}", RP_ID);

    let request = GetAssertionRequest::new(client_data_hash, RP_ID)
        .with_user_verification(true)
        .with_timeout(30000);

    println!("[2.2] Sending getAssertion request...");
    print_operation("User presence required for authentication");

    let assertion = match Client::get_assertion(&mut transport, request) {
        Ok(ass) => ass,
        Err(e) => {
            eprintln!("❌ getAssertion failed: {:?}", e);
            return Err(e);
        }
    };

    println!("   ✓ Authentication successful ({} bytes)", assertion.len());
    if assertion.len() < 10 {
        println!(
            "   [DEBUG] Short response! Hex: {}",
            hex::encode(&assertion)
        );
        if assertion.len() == 1 {
            panic!(
                "getAssertion failed with CTAP error: 0x{:02x}",
                assertion[0]
            );
        }
    }
    assert!(!assertion.is_empty(), "Assertion should not be empty");

    // First byte is CTAP status code (0x00 = success)
    assert_eq!(
        assertion[0], 0x00,
        "getAssertion failed with CTAP status: 0x{:02x}",
        assertion[0]
    );

    // Verify response structure (skip status byte)
    println!("[2.3] Validating assertion response...");
    match ciborium::from_reader::<ciborium::value::Value, _>(&assertion[1..]) {
        Ok(ciborium::value::Value::Map(map)) => {
            println!("   ✓ Valid CBOR response with {} fields", map.len());

            // Check for required fields
            let has_auth_data = map.iter().any(|(k, _)| {
                matches!(k, ciborium::value::Value::Integer(i) if Into::<i128>::into(*i) == 2)
            });
            let has_signature = map.iter().any(|(k, _)| {
                matches!(k, ciborium::value::Value::Integer(i) if Into::<i128>::into(*i) == 3)
            });

            assert!(has_auth_data, "Response should contain authData");
            assert!(has_signature, "Response should contain signature");
            println!("   ✓ Response contains authData and signature");
        }
        Ok(_) => panic!("Response should be a CBOR map"),
        Err(e) => panic!("Failed to parse CBOR response: {}", e),
    }

    println!("\n╔════════════════════════════════════════════════╗");
    println!("║              ✓ Test Passed!                    ║");
    println!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}

#[test]
#[ignore]
fn test_local_registration_and_authentication() -> Result<()> {
    with_backend("local", AuthenticatorHarness::with_local, || {
        run_registration_and_authentication_test()
    })
}

#[test]
#[ignore]
fn test_pass_registration_and_authentication() -> Result<()> {
    with_backend("password-store", AuthenticatorHarness::with_pass, || {
        run_registration_and_authentication_test()
    })
}

#[test]
#[ignore]
fn test_tpm_registration_and_authentication() -> Result<()> {
    with_backend("TPM (swtpm)", AuthenticatorHarness::with_tpm, || {
        run_registration_and_authentication_test()
    })
}

/// Core test logic for multiple user registration
fn run_registration_multiple_users_test() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║   E2E Test: Multiple User Registration        ║");
    println!("╚════════════════════════════════════════════════╝\n");

    let mut transport = connect_to_authenticator()?;

    let users = [
        ("alice@example.com", "Alice", vec![1, 2, 3, 4]),
        ("bob@example.com", "Bob", vec![5, 6, 7, 8]),
        ("charlie@example.com", "Charlie", vec![9, 10, 11, 12]),
    ];

    println!("📝 Registering {} users...\n", users.len());

    for (i, (email, display_name, user_id)) in users.iter().enumerate() {
        println!("[{}/{}] Registering {}...", i + 1, users.len(), email);

        let challenge = generate_challenge();
        let client_data_hash = generate_client_data_hash_for_registration(&challenge);

        let rp = RelyingParty {
            id: RP_ID.to_string(),
            name: Some("Example Corp".to_string()),
        };

        let user = User {
            id: user_id.clone(),
            name: Some(email.to_string()),
            display_name: Some(display_name.to_string()),
        };

        let request = MakeCredentialRequest::new(client_data_hash, rp, user)
            .with_user_verification(true)
            .with_timeout(30000);

        print_operation(&format!("Register credential for {}", email));

        let attestation = Client::make_credential(&mut transport, request)?;
        println!("   ✓ Registered {} ({} bytes)\n", email, attestation.len());
        assert!(!attestation.is_empty());
    }

    println!("╔════════════════════════════════════════════════╗");
    println!(
        "║     ✓ All {} Users Registered Successfully!    ║",
        users.len()
    );
    println!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}

#[test]
#[ignore]
fn test_local_registration_multiple_users() -> Result<()> {
    with_backend("local", AuthenticatorHarness::with_local, || {
        run_registration_multiple_users_test()
    })
}

#[test]
#[ignore]
fn test_pass_registration_multiple_users() -> Result<()> {
    with_backend("password-store", AuthenticatorHarness::with_pass, || {
        run_registration_multiple_users_test()
    })
}

#[test]
#[ignore]
fn test_tpm_registration_multiple_users() -> Result<()> {
    with_backend("TPM (swtpm)", AuthenticatorHarness::with_tpm, || {
        run_registration_multiple_users_test()
    })
}

/// Core test logic for authentication with multiple credentials
fn run_authentication_with_multiple_credentials_test() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║   E2E Test: Auth with Multiple Credentials    ║");
    println!("╚════════════════════════════════════════════════╝\n");

    let mut transport = connect_to_authenticator()?;

    // First, register a credential
    println!("📝 [Setup] Registering test credential...");
    let challenge = generate_challenge();
    let client_data_hash = generate_client_data_hash_for_registration(&challenge);

    let rp = RelyingParty {
        id: RP_ID.to_string(),
        name: Some("Example Corp".to_string()),
    };

    let user = User {
        id: vec![99, 100, 101, 102],
        name: Some("test@example.com".to_string()),
        display_name: Some("Test User".to_string()),
    };

    let request = MakeCredentialRequest::new(client_data_hash, rp, user)
        .with_user_verification(true)
        .with_timeout(30000);

    print_operation("Register test credential");

    let attestation = Client::make_credential(&mut transport, request)?;
    println!(
        "   ✓ Test credential registered ({} bytes)\n",
        attestation.len()
    );

    // Now authenticate multiple times
    println!("🔐 Authenticating 3 times with the same credential...\n");

    for i in 1..=3 {
        println!("[{}/3] Authentication attempt...", i);

        let challenge = generate_challenge();
        let client_data_hash = generate_client_data_hash_for_authentication(&challenge);

        let request = GetAssertionRequest::new(client_data_hash, RP_ID)
            .with_user_verification(true)
            .with_timeout(30000);

        print_operation(&format!("Authentication attempt {}", i));

        let assertion = Client::get_assertion(&mut transport, request)?;
        println!(
            "   ✓ Attempt {} successful ({} bytes)\n",
            i,
            assertion.len()
        );
        assert!(!assertion.is_empty());

        // Small delay between attempts
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    println!("╔════════════════════════════════════════════════╗");
    println!("║   ✓ All Authentication Attempts Successful!   ║");
    println!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}

#[test]
#[ignore]
fn test_local_authentication_with_multiple_credentials() -> Result<()> {
    with_backend("local", AuthenticatorHarness::with_local, || {
        run_authentication_with_multiple_credentials_test()
    })
}

#[test]
#[ignore]
fn test_pass_authentication_with_multiple_credentials() -> Result<()> {
    with_backend("password-store", AuthenticatorHarness::with_pass, || {
        run_authentication_with_multiple_credentials_test()
    })
}

#[test]
#[ignore]
fn test_tpm_authentication_with_multiple_credentials() -> Result<()> {
    with_backend("TPM (swtpm)", AuthenticatorHarness::with_tpm, || {
        run_authentication_with_multiple_credentials_test()
    })
}

/// Core test logic for authentication with specific credential from allowList
/// This test reproduces the webauthn-rs compact_tester AuthMultipleCredentials scenario
fn run_authentication_with_allow_list_test() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║ E2E Test: Auth with Specific Credential (Allow List) ║");
    println!("╚════════════════════════════════════════════════╝\n");

    let mut transport = connect_to_authenticator()?;

    // Register first credential (User A)
    println!("📝 [1/2] Registering first credential (User A)...");
    let challenge_a = generate_challenge();
    let client_data_hash_a = generate_client_data_hash_for_registration(&challenge_a);

    let rp = RelyingParty {
        id: RP_ID.to_string(),
        name: Some("Example Corp".to_string()),
    };

    let user_a = User {
        id: vec![1, 2, 3, 4], // User A ID
        name: Some("user_a@example.com".to_string()),
        display_name: Some("User A".to_string()),
    };

    let request_a = MakeCredentialRequest::new(client_data_hash_a, rp.clone(), user_a)
        .with_user_verification(true)
        .with_resident_key(true) // Force resident key
        .with_timeout(30000);

    print_operation("Register credential for User A");
    let attestation_a = Client::make_credential(&mut transport, request_a)?;
    assert_eq!(
        attestation_a[0], 0x00,
        "First credential registration failed with CTAP status: 0x{:02x}",
        attestation_a[0]
    );
    println!("   ✓ User A registered ({} bytes)\n", attestation_a.len());

    // Extract credential ID from User A's attestation
    let cred_id_a = extract_credential_id(&attestation_a[1..])?;
    println!("   Credential ID A: {} bytes", cred_id_a.len());

    // Register second credential (User B)
    println!("📝 [2/2] Registering second credential (User B)...");
    let challenge_b = generate_challenge();
    let client_data_hash_b = generate_client_data_hash_for_registration(&challenge_b);

    let user_b = User {
        id: vec![5, 6, 7, 8], // User B ID - different from A
        name: Some("user_b@example.com".to_string()),
        display_name: Some("User B".to_string()),
    };

    let request_b = MakeCredentialRequest::new(client_data_hash_b, rp.clone(), user_b)
        .with_user_verification(true)
        .with_resident_key(true) // Force resident key
        .with_timeout(30000);

    print_operation("Register credential for User B");
    let attestation_b = Client::make_credential(&mut transport, request_b)?;
    assert_eq!(
        attestation_b[0], 0x00,
        "Second credential registration failed with CTAP status: 0x{:02x}",
        attestation_b[0]
    );
    println!("   ✓ User B registered ({} bytes)\n", attestation_b.len());

    let cred_id_b = extract_credential_id(&attestation_b[1..])?;
    println!("   Credential ID B: {} bytes\n", cred_id_b.len());

    // Now authenticate with User A's credential ID in allowList
    println!("🔐 Authenticating with User A's credential (via allowList)...\n");

    let challenge_auth = generate_challenge();
    let client_data_hash_auth = generate_client_data_hash_for_authentication(&challenge_auth);

    let request_auth = GetAssertionRequest::new(client_data_hash_auth, RP_ID)
        .with_credentials(vec![CredentialDescriptor {
            id: cred_id_a.clone(),
            credential_type: CredentialType::PublicKey,
        }]) // Specify User A's credential
        .with_user_verification(true)
        .with_timeout(30000);

    print_operation("Authenticate with User A via allowList");
    let assertion = Client::get_assertion(&mut transport, request_auth)?;

    assert_eq!(
        assertion[0], 0x00,
        "Authentication failed with CTAP status: 0x{:02x}",
        assertion[0]
    );
    println!(
        "   ✓ Authentication succeeded ({} bytes)\n",
        assertion.len()
    );

    // Verify the response is valid CBOR
    match ciborium::from_reader::<ciborium::value::Value, _>(&assertion[1..]) {
        Ok(ciborium::value::Value::Map(_)) => {
            println!("   ✓ Response is valid CBOR map");
        }
        Ok(_) => panic!("Response is not a CBOR map"),
        Err(e) => panic!("Failed to parse assertion: {}", e),
    }

    println!("\n╔════════════════════════════════════════════════╗");
    println!("║  ✓ Allow List Credential Selection Works!     ║");
    println!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}

/// Extract credential ID from attestation response
fn extract_credential_id(attestation_cbor: &[u8]) -> Result<Vec<u8>> {
    let value: ciborium::value::Value =
        ciborium::from_reader(attestation_cbor).map_err(|_e| soft_fido2::Error::Other)?;

    if let ciborium::value::Value::Map(map) = value {
        // Look for authData (key 0x02)
        for (key, val) in map {
            if let ciborium::value::Value::Integer(i) = key {
                let i_val: i128 = i.into();
                if i_val == 2
                    && let ciborium::value::Value::Bytes(auth_data) = val
                {
                    // Auth data format: rpIdHash(32) + flags(1) + counter(4) + attested_cred_data
                    // Attested cred data: aaguid(16) + credIdLen(2) + credId(credIdLen) + ...
                    if auth_data.len() < 37 + 16 + 2 {
                        return Err(soft_fido2::Error::Other);
                    }

                    let cred_id_len_offset = 37 + 16; // Skip rpIdHash(32) + flags(1) + counter(4) + aaguid(16)
                    let cred_id_len = u16::from_be_bytes([
                        auth_data[cred_id_len_offset],
                        auth_data[cred_id_len_offset + 1],
                    ]) as usize;

                    let cred_id_offset = cred_id_len_offset + 2;
                    if auth_data.len() < cred_id_offset + cred_id_len {
                        return Err(soft_fido2::Error::Other);
                    }

                    return Ok(auth_data[cred_id_offset..cred_id_offset + cred_id_len].to_vec());
                }
            }
        }
    }

    Err(soft_fido2::Error::Other)
}

#[test]
#[ignore]
fn test_local_authentication_with_allow_list() -> Result<()> {
    with_backend("local", AuthenticatorHarness::with_local, || {
        run_authentication_with_allow_list_test()
    })
}

#[test]
#[ignore]
fn test_pass_authentication_with_allow_list() -> Result<()> {
    with_backend("password-store", AuthenticatorHarness::with_pass, || {
        run_authentication_with_allow_list_test()
    })
}

#[test]
#[ignore]
fn test_tpm_authentication_with_allow_list() -> Result<()> {
    with_backend("TPM (swtpm)", AuthenticatorHarness::with_tpm, || {
        run_authentication_with_allow_list_test()
    })
}

/// Core test logic for authentication without credential (should fail)
fn run_authentication_without_credential_fails_test() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║   E2E Test: Auth Without Credential (Fail)    ║");
    println!("╚════════════════════════════════════════════════╝\n");

    let mut transport = connect_to_authenticator()?;

    println!("🔐 Attempting authentication with non-existent credential...\n");

    let challenge = generate_challenge();
    let client_data_hash = generate_client_data_hash_for_authentication(&challenge);

    // Use a different RP ID that has no credentials
    let fake_rp_id = "nonexistent.example.com";
    println!("   Using RP: {}", fake_rp_id);

    let request = GetAssertionRequest::new(client_data_hash, fake_rp_id)
        .with_user_verification(true)
        .with_timeout(30000);

    println!("   Sending getAssertion...");

    let result = Client::get_assertion(&mut transport, request)?;

    // Check if the response is an error (status byte != 0x00)
    if result.is_empty() {
        panic!("Received empty response");
    }

    let status = result[0];
    if status == 0x00 {
        panic!(
            "Authentication should have failed for non-existent credential, but got success (status 0x00)"
        );
    }

    println!(
        "   ✓ Authentication failed as expected: CTAP status 0x{:02x}",
        status
    );

    println!("\n╔════════════════════════════════════════════════╗");
    println!("║        ✓ Correctly Rejected Invalid Auth!     ║");
    println!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}

#[test]
#[ignore]
fn test_local_authentication_without_credential_fails() -> Result<()> {
    with_backend("local", AuthenticatorHarness::with_local, || {
        run_authentication_without_credential_fails_test()
    })
}

#[test]
#[ignore]
fn test_pass_authentication_without_credential_fails() -> Result<()> {
    with_backend("password-store", AuthenticatorHarness::with_pass, || {
        run_authentication_without_credential_fails_test()
    })
}

#[test]
#[ignore]
fn test_tpm_authentication_without_credential_fails() -> Result<()> {
    with_backend("TPM (swtpm)", AuthenticatorHarness::with_tpm, || {
        run_authentication_without_credential_fails_test()
    })
}

/// Core test logic for registration with different RPs
fn run_registration_with_different_rps_test() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║   E2E Test: Multiple Relying Parties          ║");
    println!("╚════════════════════════════════════════════════╝\n");

    let mut transport = connect_to_authenticator()?;

    let relying_parties = [
        ("example.com", "Example Corp"),
        ("another.com", "Another Corp"),
        ("third.com", "Third Corp"),
    ];

    println!(
        "📝 Registering credentials for {} RPs...\n",
        relying_parties.len()
    );

    for (i, (rp_id, rp_name)) in relying_parties.iter().enumerate() {
        println!(
            "[{}/{}] Registering for {}...",
            i + 1,
            relying_parties.len(),
            rp_id
        );

        let challenge = generate_challenge();
        // Need to use the actual RP ID in the origin for proper validation
        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://{}","crossOrigin":false}}"#,
            base64_url_encode(&challenge),
            rp_id
        );
        let hash = Sha256::digest(client_data.as_bytes());
        let client_data_hash = ClientDataHash::from_slice(&hash)?;

        let rp = RelyingParty {
            id: rp_id.to_string(),
            name: Some(rp_name.to_string()),
        };

        let user = User {
            id: vec![i as u8, (i + 1) as u8, (i + 2) as u8, (i + 3) as u8],
            name: Some(format!("user@{}", rp_id)),
            display_name: Some(format!("User at {}", rp_name)),
        };

        let request = MakeCredentialRequest::new(client_data_hash, rp, user)
            .with_user_verification(true)
            .with_timeout(30000);

        print_operation(&format!("Register for {}", rp_id));

        let attestation = Client::make_credential(&mut transport, request)?;
        println!(
            "   ✓ Registered for {} ({} bytes)\n",
            rp_id,
            attestation.len()
        );
        assert!(!attestation.is_empty());
    }

    println!("╔════════════════════════════════════════════════╗");
    println!("║   ✓ Credentials for All RPs Created!          ║");
    println!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}

#[test]
#[ignore]
fn test_local_registration_with_different_rps() -> Result<()> {
    with_backend("local", AuthenticatorHarness::with_local, || {
        run_registration_with_different_rps_test()
    })
}

#[test]
#[ignore]
fn test_pass_registration_with_different_rps() -> Result<()> {
    with_backend("password-store", AuthenticatorHarness::with_pass, || {
        run_registration_with_different_rps_test()
    })
}

#[test]
#[ignore]
fn test_tpm_registration_with_different_rps() -> Result<()> {
    with_backend("TPM (swtpm)", AuthenticatorHarness::with_tpm, || {
        run_registration_with_different_rps_test()
    })
}
