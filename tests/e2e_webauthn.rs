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
//! These tests require the passless authenticator to be running in a separate terminal.
//!
//! ## Setup:
//! ```bash
//! # Terminal 1: Start authenticator with E2E test mode (auto-accepts UV)
//! PASSLESS_E2E_AUTO_ACCEPT_UV=1 cargo run
//!
//! # Terminal 2: Run tests
//! cargo test --test e2e_webauthn --test-threads=1 -- --ignored
//! ```
//!
//! Note: The PASSLESS_E2E_AUTO_ACCEPT_UV environment variable is only available
//! in debug builds and will be ignored in release builds for security.
//!

use keylib::client::{
    Client, ClientDataHash, GetAssertionRequest, MakeCredentialRequest, TransportList, User,
};
use keylib::credential::RelyingParty;
use keylib::error::Result;
use sha2::{Digest, Sha256};
use std::io::Write;

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

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
fn connect_to_authenticator() -> Result<keylib::client::Transport> {
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
        return Err(keylib::Error::Other);
    }

    println!("   ✓ Found {} authenticator(s)", list.len());

    let transport = list.get(0).ok_or(keylib::Error::Other)?;

    // Note: We don't call transport.open() here because the authenticator
    // has already created a UHID virtual device that's accessible via USB HID.
    // Multiple clients can communicate with it without explicitly opening.
    println!("   ✓ Connected to authenticator\n");
    Ok(transport)
}

#[test]
#[ignore] // Run with: cargo test --test e2e_webauthn -- --ignored --test-threads=1
fn test_complete_registration_and_authentication_flow() -> Result<()> {
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
        name: "alice@example.com".to_string(),
        display_name: Some("Alice".to_string()),
    };

    println!("   RP: {}", rp.id);
    println!("   User: {}", user.name);

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
    assert!(!attestation.is_empty(), "Attestation should not be empty");

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
    assert!(!assertion.is_empty(), "Assertion should not be empty");

    // Verify response structure
    println!("[2.3] Validating assertion response...");
    match ciborium::from_reader::<ciborium::value::Value, _>(assertion.as_slice()) {
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
fn test_registration_multiple_users() -> Result<()> {
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
            name: email.to_string(),
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
fn test_authentication_with_multiple_credentials() -> Result<()> {
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
        name: "test@example.com".to_string(),
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
fn test_authentication_without_credential_fails() -> Result<()> {
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

    match Client::get_assertion(&mut transport, request) {
        Ok(_) => {
            panic!("Authentication should have failed for non-existent credential");
        }
        Err(e) => {
            println!("   ✓ Authentication failed as expected: {:?}", e);
        }
    }

    println!("\n╔════════════════════════════════════════════════╗");
    println!("║        ✓ Correctly Rejected Invalid Auth!     ║");
    println!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}

#[test]
#[ignore]
fn test_registration_with_different_rps() -> Result<()> {
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
            name: format!("user@{}", rp_id),
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
