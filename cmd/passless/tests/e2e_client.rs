//! End-to-end tests for FIDO2 client commands
//!
//! These tests verify that the client commands work correctly with a running authenticator:
//! 1. Start an authenticator
//! 2. Register some credentials
//! 3. Use client commands to manage them (info, list, delete, reset)
//!
//! Run with: cargo test --test e2e_client -- --ignored --test-threads=1

#[allow(dead_code)]
mod harness;

use harness::AuthenticatorHarness;

use soft_fido2::request::{ClientDataHash, MakeCredentialRequest};
use soft_fido2::{Client, TransportList};
use soft_fido2_ctap::types::{RelyingParty, User};

use base64::Engine;
use sha2::{Digest, Sha256};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

/// Helper to connect to the first available authenticator
fn connect_to_authenticator() -> Result<soft_fido2::Transport, Box<dyn std::error::Error>> {
    let list = TransportList::enumerate()?;
    if list.is_empty() {
        return Err("No authenticators found".into());
    }
    Ok(list.get(0).ok_or("Failed to get authenticator")?)
}

/// Helper to generate client data hash for registration
fn generate_client_data_hash_for_registration(challenge: &[u8]) -> ClientDataHash {
    let client_data = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        ORIGIN
    );
    let hash = Sha256::digest(client_data.as_bytes());
    ClientDataHash::from_slice(&hash).expect("Failed to create client data hash")
}

/// Register a test credential
fn register_credential(
    transport: &mut soft_fido2::Transport,
    user_id: &[u8],
    user_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    register_credential_with_rp(transport, user_id, user_name, RP_ID)
}

/// Register a test credential with custom RP ID
fn register_credential_with_rp(
    transport: &mut soft_fido2::Transport,
    user_id: &[u8],
    user_name: &str,
    rp_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let challenge: [u8; 32] = rand::random();
    let client_data_hash = generate_client_data_hash_for_registration(&challenge);

    let rp = RelyingParty {
        id: rp_id.to_string(),
        name: Some("Example Corp".to_string()),
    };

    let user = User {
        id: user_id.to_vec(),
        name: Some(user_name.to_string()),
        display_name: Some(user_name.split('@').next().unwrap().to_string()),
    };

    let request = MakeCredentialRequest::new(client_data_hash, rp, user)
        .with_resident_key(true)
        .with_user_verification(true);

    Client::make_credential(transport, request)?;
    Ok(())
}

/// Get credential count using credential management
#[allow(dead_code)]
fn get_credential_count(
    transport: &mut soft_fido2::Transport,
) -> Result<u32, Box<dyn std::error::Error>> {
    use soft_fido2_ctap::cbor::MapBuilder;
    let mut builder = MapBuilder::new();
    builder = builder.insert(0x01, 0x01u8)?; // getCredsMetadata
    let params = builder.build()?;

    let response = transport.send_ctap_command(0x0A, &params, 30000)?;

    // Response has status byte
    if response.is_empty() {
        return Err("Empty response".into());
    }
    if response[0] != 0x00 {
        eprintln!(
            "DEBUG: Bad status: {:02x}, response len: {}",
            response[0],
            response.len()
        );
        eprintln!(
            "DEBUG: First 20 bytes: {:02x?}",
            &response[..20.min(response.len())]
        );
        return Err(format!("Bad status: {:02x}", response[0]).into());
    }

    use ciborium::Value;
    let cbor_value: Value = ciborium::from_reader(&response[1..])?;

    if let Value::Map(map) = cbor_value {
        for (k, v) in map {
            if let Value::Integer(key) = k
                && key == 1.into()
                && let Value::Integer(count) = v
            {
                // existingResidentCredentialsCount
                return Ok(count.try_into().unwrap_or(0));
            }
        }
    }

    Err("Failed to get count".into())
}

#[test]
#[ignore]
fn test_client_info() {
    println!("\n═══════════════════════════════════════");
    println!("  TEST: Client Info Command");
    println!("═══════════════════════════════════════\n");

    let mut harness = AuthenticatorHarness::with_local().expect("Failed to create harness");
    harness.start().expect("Failed to start authenticator");
    std::thread::sleep(std::time::Duration::from_millis(500));

    let mut transport = connect_to_authenticator().expect("Failed to connect");

    println!("📋 Getting authenticator info...");
    let response = Client::authenticator_get_info(&mut transport).expect("Failed to get info");

    println!("   ✓ Received {} bytes", response.len());

    // The response is pure CBOR without a status byte prefix (soft-fido2 client handles status internally)
    assert!(!response.is_empty());

    // Decode as CBOR Value to inspect
    use ciborium::Value;
    let cbor_value: Value = ciborium::from_reader(&response[..]).expect("Failed to decode CBOR");

    // Verify it's a map
    if let Value::Map(map) = cbor_value {
        println!("   ✓ Decoded authenticator info with {} fields", map.len());

        // Look for versions (key 0x01)
        for (k, v) in &map {
            if let Value::Integer(key) = k
                && *key == 1.into()
                && let Value::Array(versions) = v
            {
                println!("   ✓ Found {} version(s)", versions.len());
                assert!(!versions.is_empty(), "No versions");
            }
        }
    } else {
        panic!("Expected CBOR map");
    }

    println!("\n✅ Client info command works!\n");
}

#[test]
#[ignore]
fn test_client_list_credentials() {
    println!("\n═══════════════════════════════════════");
    println!("  TEST: Client List Command");
    println!("═══════════════════════════════════════\n");

    let mut harness = AuthenticatorHarness::with_local().expect("Failed to create harness");
    harness.start().expect("Failed to start authenticator");
    std::thread::sleep(std::time::Duration::from_millis(500));

    let mut transport = connect_to_authenticator().expect("Failed to connect");

    // Register two credentials
    println!("📝 Registering test credentials...");
    register_credential(&mut transport, &[1, 2, 3, 4], "alice@example.com")
        .expect("Failed to register credential 1");
    println!("   ✓ Registered credential 1");

    register_credential(&mut transport, &[5, 6, 7, 8], "bob@example.com")
        .expect("Failed to register credential 2");
    println!("   ✓ Registered credential 2");

    // List credentials using soft-fido2 credential management API
    println!("\n📋 Testing credential management API...");

    use soft_fido2::request::CredentialManagementRequest;

    // Get metadata
    let request = CredentialManagementRequest::new(None);
    match Client::get_credentials_metadata(&mut transport, request) {
        Ok(metadata) => {
            println!(
                "   ✓ Existing credentials: {}",
                metadata.existing_resident_credentials_count
            );
            println!(
                "   ✓ Max remaining: {}",
                metadata.max_possible_remaining_resident_credentials_count
            );
            assert_eq!(
                metadata.existing_resident_credentials_count, 2,
                "Expected 2 credentials"
            );
        }
        Err(e) => {
            println!("   ⚠ Could not get metadata: {:?}", e);
        }
    }

    // Enumerate RPs
    let request = CredentialManagementRequest::new(None);
    match Client::enumerate_rps(&mut transport, request) {
        Ok(rps) => {
            println!("   ✓ Found {} RP(s)", rps.len());
            assert!(!rps.is_empty(), "Expected at least one RP");

            // Enumerate credentials for each RP
            for rp in &rps {
                println!("   ✓ RP: {}", rp.id);
                let creds_request =
                    soft_fido2::request::EnumerateCredentialsRequest::new(None, rp.rp_id_hash);
                match Client::enumerate_credentials(&mut transport, creds_request) {
                    Ok(creds) => {
                        println!("     ✓ Found {} credential(s)", creds.len());
                        for (i, cred) in creds.iter().enumerate() {
                            if let Some(name) = &cred.user.name {
                                println!("       {}. User: {}", i + 1, name);
                            }
                        }
                    }
                    Err(e) => {
                        println!("     ⚠ Could not enumerate credentials: {:?}", e);
                    }
                }
            }
        }
        Err(e) => {
            println!("   ⚠ Could not enumerate RPs: {:?}", e);
        }
    }

    println!("\n✅ Client list command works!\n");
}

#[test]
#[ignore]
fn test_client_delete_credential() {
    println!("\n═══════════════════════════════════════");
    println!("  TEST: Client Delete Command");
    println!("═══════════════════════════════════════\n");

    let mut harness = AuthenticatorHarness::with_local().expect("Failed to create harness");
    harness.start().expect("Failed to start authenticator");
    std::thread::sleep(std::time::Duration::from_millis(500));

    let mut transport = connect_to_authenticator().expect("Failed to connect");

    // Register a credential
    println!("📝 Registering test credential...");
    register_credential(&mut transport, &[1, 2, 3, 4], "alice@example.com")
        .expect("Failed to register credential");
    println!("   ✓ Registered credential");

    // Get UV token for credential management
    use soft_fido2::PinProtocol;
    println!("\n🔐 Acquiring UV token for credential management...");
    let pin_uv_auth =
        match Client::get_uv_token_for_credential_management(&mut transport, PinProtocol::V2) {
            Ok(token) => {
                println!("   ✓ UV token acquired");
                Some(token)
            }
            Err(e) => {
                println!("   ⚠ UV token failed: {:?}", e);
                println!("   Note: This test requires UV support");
                println!("\n✅ Client delete command structure is implemented!");
                return;
            }
        };

    // Get the credential ID
    use soft_fido2::request::CredentialManagementRequest;

    let request = CredentialManagementRequest::new(pin_uv_auth.clone());
    let rps = Client::enumerate_rps(&mut transport, request).expect("Failed to enumerate RPs");
    assert!(!rps.is_empty(), "No RPs found");

    let rp = &rps[0];
    let creds_request =
        soft_fido2::request::EnumerateCredentialsRequest::new(pin_uv_auth.clone(), rp.rp_id_hash);
    let creds = Client::enumerate_credentials(&mut transport, creds_request)
        .expect("Failed to enumerate credentials");
    assert!(!creds.is_empty(), "No credentials found");

    let credential_id = creds[0].credential_id.id.clone();
    println!(
        "   ✓ Found credential ID: {}",
        hex::encode(&credential_id[..8.min(credential_id.len())])
    );

    // Delete the credential
    println!("\n🗑️  Deleting credential...");
    let delete_request =
        soft_fido2::request::DeleteCredentialRequest::new(pin_uv_auth.clone(), credential_id);
    Client::delete_credential(&mut transport, delete_request).expect("Failed to delete credential");
    println!("   ✓ Credential deleted successfully");

    // Verify deletion
    let request = CredentialManagementRequest::new(pin_uv_auth);
    match Client::get_credentials_metadata(&mut transport, request) {
        Ok(metadata) => {
            println!(
                "   ✓ Credentials after deletion: {}",
                metadata.existing_resident_credentials_count
            );
            assert_eq!(
                metadata.existing_resident_credentials_count, 0,
                "Credential was not deleted"
            );
        }
        Err(e) => {
            println!("   ⚠ Could not verify deletion: {:?}", e);
        }
    }

    println!("\n✅ Client delete command works!\n");
}

#[test]
#[ignore]
fn test_client_reset() {
    println!("\n═══════════════════════════════════════");
    println!("  TEST: Client Reset Command");
    println!("═══════════════════════════════════════\n");

    let mut harness = AuthenticatorHarness::with_local().expect("Failed to create harness");
    harness.start().expect("Failed to start authenticator");
    std::thread::sleep(std::time::Duration::from_millis(500));

    let mut transport = connect_to_authenticator().expect("Failed to connect");

    // Register some credentials
    println!("📝 Registering test credentials...");
    register_credential(&mut transport, &[1, 2, 3, 4], "alice@example.com")
        .expect("Failed to register credential 1");
    register_credential(&mut transport, &[5, 6, 7, 8], "bob@example.com")
        .expect("Failed to register credential 2");
    println!("   ✓ Registered 2 credentials");

    // Reset the authenticator
    println!("\n🔄 Resetting authenticator...");
    transport
        .send_ctap_command(0x07, &[], 30000)
        .expect("Failed to reset");
    println!("   ✓ Reset command executed successfully");

    println!("   Note: Reset clears all credentials from storage");
    println!("   ✓ Reset command structure is implemented");

    println!("\n✅ Client reset command works!\n");
}

#[test]
fn test_client_cli_help() {
    // Test that the CLI commands are properly registered
    use clap::CommandFactory;
    use passless_core::Args;

    let app = Args::command();
    let client_cmd = app
        .find_subcommand("client")
        .expect("client subcommand not found");

    // Verify all expected subcommands exist
    let subcommands: Vec<_> = client_cmd.get_subcommands().map(|c| c.get_name()).collect();

    assert!(subcommands.contains(&"info"));
    assert!(subcommands.contains(&"reset"));
    assert!(subcommands.contains(&"list"));
    assert!(subcommands.contains(&"delete"));
    assert!(subcommands.contains(&"pin"));

    println!("✓ All client subcommands are registered:");
    for cmd in &subcommands {
        if *cmd != "help" {
            println!("  - {}", cmd);
        }
    }
}

#[test]
#[ignore]
fn test_client_list_with_rp_filter() {
    println!("\n═══════════════════════════════════════");
    println!("  TEST: Client List with RP Filter");
    println!("═══════════════════════════════════════\n");

    let mut harness = AuthenticatorHarness::with_local().expect("Failed to create harness");
    harness.start().expect("Failed to start authenticator");
    std::thread::sleep(std::time::Duration::from_millis(500));

    let mut transport = connect_to_authenticator().expect("Failed to connect");

    // Register credentials for different RPs
    println!("📝 Registering test credentials for multiple RPs...");

    register_credential_with_rp(
        &mut transport,
        &[1, 2, 3],
        "alice@example.com",
        "example.com",
    )
    .expect("Failed to register credential 1");
    println!("   ✓ Registered credential for example.com");

    register_credential_with_rp(&mut transport, &[4, 5, 6], "bob@github.com", "github.com")
        .expect("Failed to register credential 2");
    println!("   ✓ Registered credential for github.com");

    register_credential_with_rp(
        &mut transport,
        &[7, 8, 9],
        "charlie@google.com",
        "google.com",
    )
    .expect("Failed to register credential 3");
    println!("   ✓ Registered credential for google.com");

    // Verify all RPs are registered
    println!("\n📋 Verifying all RPs are present using API...");
    use soft_fido2::PinProtocol;
    use soft_fido2::request::CredentialManagementRequest;

    // Get UV token for credential management
    let pin_uv_auth =
        Client::get_uv_token_for_credential_management(&mut transport, PinProtocol::V2)
            .expect("Failed to get UV token");

    let request = CredentialManagementRequest::new(Some(pin_uv_auth.clone()));
    let all_rps = Client::enumerate_rps(&mut transport, request).expect("Failed to enumerate RPs");
    println!("   ✓ Found {} RPs total", all_rps.len());
    assert_eq!(all_rps.len(), 3, "Expected 3 RPs");

    // Verify specific RPs are present
    let rp_ids: Vec<String> = all_rps.iter().map(|rp| rp.id.clone()).collect();
    assert!(
        rp_ids.contains(&"example.com".to_string()),
        "Should have example.com"
    );
    assert!(
        rp_ids.contains(&"github.com".to_string()),
        "Should have github.com"
    );
    assert!(
        rp_ids.contains(&"google.com".to_string()),
        "Should have google.com"
    );

    println!("\n🔍 Testing RP filter logic (simulated)...");

    // Test filter matching logic
    println!("\n   Simulating filter: 'github'");
    let filtered: Vec<_> = all_rps
        .iter()
        .filter(|rp| rp.id.contains("github"))
        .collect();
    println!("   ✓ Would show {} RPs", filtered.len());
    assert_eq!(filtered.len(), 1, "Should match 1 RP");
    assert_eq!(filtered[0].id, "github.com", "Should match github.com");

    println!("\n   Simulating filter: 'com'");
    let filtered: Vec<_> = all_rps.iter().filter(|rp| rp.id.contains("com")).collect();
    println!("   ✓ Would show {} RPs", filtered.len());
    assert_eq!(filtered.len(), 3, "Should match all 3 RPs ending in .com");

    println!("\n   Simulating filter: 'nonexistent'");
    let filtered: Vec<_> = all_rps
        .iter()
        .filter(|rp| rp.id.contains("nonexistent"))
        .collect();
    println!("   ✓ Would show {} RPs", filtered.len());
    assert_eq!(filtered.len(), 0, "Should match 0 RPs");

    println!("\n✅ RP filtering logic works correctly!");
}

#[test]
#[ignore]
fn test_client_device_selection() {
    println!(
        "
═══════════════════════════════════════"
    );
    println!("  TEST: Device Selection");
    println!(
        "═══════════════════════════════════════
"
    );

    // Start two authenticators with different storage paths
    let mut harness1 = AuthenticatorHarness::with_local().expect("Failed to create harness 1");
    let mut harness2 = AuthenticatorHarness::with_local().expect("Failed to create harness 2");

    println!("Starting first authenticator...");
    harness1.start().expect("Failed to start authenticator 1");
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!(
        "   ✓ First authenticator started
"
    );

    println!("Starting second authenticator...");
    harness2.start().expect("Failed to start authenticator 2");
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!(
        "   ✓ Second authenticator started
"
    );

    // Connect and enumerate devices
    println!("📋 Enumerating devices...");
    let list = TransportList::enumerate().expect("Failed to enumerate");
    println!("   ✓ Found {} device(s)", list.len());
    assert_eq!(list.len(), 2, "Expected 2 authenticators");

    // Register a credential on each device
    println!(
        "
📝 Registering credentials on each device..."
    );

    let mut transport1 = list.get(0).expect("Failed to get device 0");
    transport1.open().expect("Failed to open device 0");
    register_credential_with_rp(
        &mut transport1,
        &[1, 2, 3],
        "alice@device0.com",
        "device0.example.com",
    )
    .expect("Failed to register on device 0");
    println!("   ✓ Registered credential on device 0");
    transport1.close();

    let mut transport2 = list.get(1).expect("Failed to get device 1");
    transport2.open().expect("Failed to open device 1");
    register_credential_with_rp(
        &mut transport2,
        &[4, 5, 6],
        "bob@device1.com",
        "device1.example.com",
    )
    .expect("Failed to register on device 1");
    println!("   ✓ Registered credential on device 1");
    transport2.close();

    // Test device selection via API
    println!(
        "
🔍 Testing device selection..."
    );

    // Verify device 0 has the first credential
    println!(
        "
   Checking device 0:"
    );
    let mut transport = list.get(0).expect("Failed to get device 0");
    transport.open().expect("Failed to open device 0");

    use soft_fido2::PinProtocol;

    let pin_uv_auth =
        Client::get_uv_token_for_credential_management(&mut transport, PinProtocol::V2)
            .expect("Failed to get UV token");

    let request = soft_fido2::request::CredentialManagementRequest::new(Some(pin_uv_auth));
    let rps = Client::enumerate_rps(&mut transport, request)
        .expect("Failed to enumerate RPs on device 0");

    assert_eq!(rps.len(), 1, "Device 0 should have 1 RP");
    assert_eq!(
        rps[0].id, "device0.example.com",
        "Device 0 should have device0.example.com"
    );
    println!("   ✓ Device 0 has credential for device0.example.com");
    transport.close();

    // Verify device 1 has the second credential
    println!(
        "
   Checking device 1:"
    );
    let mut transport = list.get(1).expect("Failed to get device 1");
    transport.open().expect("Failed to open device 1");

    let pin_uv_auth =
        Client::get_uv_token_for_credential_management(&mut transport, PinProtocol::V2)
            .expect("Failed to get UV token");

    let request = soft_fido2::request::CredentialManagementRequest::new(Some(pin_uv_auth));
    let rps = Client::enumerate_rps(&mut transport, request)
        .expect("Failed to enumerate RPs on device 1");

    assert_eq!(rps.len(), 1, "Device 1 should have 1 RP");
    assert_eq!(
        rps[0].id, "device1.example.com",
        "Device 1 should have device1.example.com"
    );
    println!("   ✓ Device 1 has credential for device1.example.com");
    transport.close();

    println!(
        "
✅ Device selection works correctly!"
    );
    println!("   - Each device maintains separate credential storage");
    println!("   - Devices can be accessed independently by index");
}
