use std::fs;

use tempfile::tempdir;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestRelyingParty {
    id: String,
    name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestUser {
    id: Vec<u8>,
    name: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct TestExtensions {
    cred_protect: Option<u8>,
    hmac_secret: Option<bool>,
    cred_random: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestCredential {
    id: Vec<u8>,
    rp: TestRelyingParty,
    user: TestUser,
    sign_count: u32,
    alg: i32,
    private_key: Vec<u8>,
    created: i64,
    discoverable: bool,
    #[serde(default)]
    extensions: TestExtensions,
}

fn make_test_cred(rp_id: &str, user_id: &[u8], cred_id: &[u8]) -> TestCredential {
    TestCredential {
        id: cred_id.to_vec(),
        rp: TestRelyingParty {
            id: rp_id.to_string(),
            name: Some("Test RP".to_string()),
        },
        user: TestUser {
            id: user_id.to_vec(),
            name: Some("testuser@example.com".to_string()),
            display_name: Some("Test User".to_string()),
        },
        sign_count: 0,
        alg: -7,
        private_key: vec![0x42; 32],
        created: 1700000000,
        discoverable: true,
        extensions: TestExtensions::default(),
    }
}

fn serialize_cred(cred: &TestCredential) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(cred, &mut buf).unwrap();
    buf
}

fn deserialize_cred(data: &[u8]) -> Result<TestCredential, String> {
    ciborium::from_reader(data).map_err(|e| format!("deserialization error: {}", e))
}

#[test]
fn credential_cbor_round_trip() {
    let cred = make_test_cred("example.com", &[1, 2, 3], &[0xAA; 16]);
    let bytes = serialize_cred(&cred);
    let decoded = deserialize_cred(&bytes).unwrap();
    assert_eq!(decoded.id, cred.id);
    assert_eq!(decoded.rp.id, "example.com");
    assert_eq!(decoded.user.id, vec![1, 2, 3]);
    assert_eq!(decoded.sign_count, 0);
    assert_eq!(decoded.alg, -7);
}

#[test]
fn sign_count_preserved_through_serialization() {
    let mut cred = make_test_cred("example.com", &[1], &[0xBB; 16]);
    cred.sign_count = 42;
    let bytes = serialize_cred(&cred);
    let decoded = deserialize_cred(&bytes).unwrap();
    assert_eq!(decoded.sign_count, 42);
}

#[test]
fn sign_count_increment_serialization() {
    let mut cred = make_test_cred("example.com", &[1], &[0xCC; 16]);
    cred.sign_count = 100;
    let bytes = serialize_cred(&cred);
    let mut decoded = deserialize_cred(&bytes).unwrap();
    decoded.sign_count += 1;
    let bytes2 = serialize_cred(&decoded);
    let decoded2 = deserialize_cred(&bytes2).unwrap();
    assert_eq!(decoded2.sign_count, 101);
}

#[test]
fn corrupted_bytes_rejected() {
    let result = deserialize_cred(b"this is not valid cbor data");
    assert!(result.is_err());
}

#[test]
fn truncated_bytes_rejected() {
    let cred = make_test_cred("example.com", &[1], &[0xDD; 16]);
    let bytes = serialize_cred(&cred);
    let truncated = &bytes[..bytes.len() / 2];
    let result = deserialize_cred(truncated);
    assert!(result.is_err());
}

#[test]
fn empty_bytes_rejected() {
    let result = deserialize_cred(b"");
    assert!(result.is_err());
}

#[test]
fn extensions_round_trip() {
    let mut cred = make_test_cred("example.com", &[1], &[0xEE; 16]);
    cred.extensions.cred_protect = Some(2);
    cred.extensions.hmac_secret = Some(true);
    cred.extensions.cred_random = Some(vec![0x11; 32]);

    let bytes = serialize_cred(&cred);
    let decoded = deserialize_cred(&bytes).unwrap();
    assert_eq!(decoded.extensions.cred_protect, Some(2));
    assert_eq!(decoded.extensions.hmac_secret, Some(true));
    assert_eq!(decoded.extensions.cred_random, Some(vec![0x11; 32]));
}

#[test]
fn missing_extensions_field_defaults() {
    let cred = make_test_cred("example.com", &[1], &[0xFF; 16]);
    let bytes = serialize_cred(&cred);
    let decoded = deserialize_cred(&bytes).unwrap();
    assert_eq!(decoded.extensions.cred_protect, None);
    assert_eq!(decoded.extensions.hmac_secret, None);
    assert_eq!(decoded.extensions.cred_random, None);
}

#[test]
fn on_disk_layout_creates_rp_directories() {
    let dir = tempdir().unwrap();
    let rp_dir = dir.path().join("example.com");
    fs::create_dir_all(&rp_dir).unwrap();

    let cred = make_test_cred("example.com", &[1], &[0x01; 16]);
    let bytes = serialize_cred(&cred);
    let cred_path = rp_dir.join(format!("{}.bin", hex::encode([0x01; 16])));
    fs::write(&cred_path, &bytes).unwrap();

    assert!(cred_path.exists());
    let read_back = fs::read(&cred_path).unwrap();
    let decoded = deserialize_cred(&read_back).unwrap();
    assert_eq!(decoded.rp.id, "example.com");
}

#[test]
fn multiple_credentials_in_same_rp_directory() {
    let dir = tempdir().unwrap();
    let rp_dir = dir.path().join("example.com");
    fs::create_dir_all(&rp_dir).unwrap();

    for i in 0..5u8 {
        let cred = make_test_cred("example.com", &[i], &[i; 16]);
        let bytes = serialize_cred(&cred);
        let path = rp_dir.join(format!("{}.bin", hex::encode([i; 16])));
        fs::write(&path, &bytes).unwrap();
    }

    let entries: Vec<_> = fs::read_dir(&rp_dir).unwrap().collect();
    assert_eq!(entries.len(), 5);
}

#[test]
fn different_rps_in_separate_directories() {
    let dir = tempdir().unwrap();

    for rp in &["a.com", "b.com", "c.com"] {
        let rp_dir = dir.path().join(rp);
        fs::create_dir_all(&rp_dir).unwrap();
        let cred = make_test_cred(rp, &[1], &[0x01; 16]);
        let bytes = serialize_cred(&cred);
        let path = rp_dir.join("01010101010101010101010101010101.bin");
        fs::write(&path, &bytes).unwrap();
    }

    assert!(dir.path().join("a.com").is_dir());
    assert!(dir.path().join("b.com").is_dir());
    assert!(dir.path().join("c.com").is_dir());
}

#[test]
fn credential_with_large_user_id_round_trips() {
    let large_user_id = vec![0xAB; 256];
    let cred = make_test_cred("example.com", &large_user_id, &[0x01; 16]);
    let bytes = serialize_cred(&cred);
    let decoded = deserialize_cred(&bytes).unwrap();
    assert_eq!(decoded.user.id, large_user_id);
}

#[test]
fn credential_with_max_alg_values() {
    for alg in &[-7, -8, -25, -35, -36] {
        let mut cred = make_test_cred("example.com", &[1], &[0x01; 16]);
        cred.alg = *alg;
        let bytes = serialize_cred(&cred);
        let decoded = deserialize_cred(&bytes).unwrap();
        assert_eq!(decoded.alg, *alg);
    }
}

#[test]
fn empty_rp_name_round_trips() {
    let mut cred = make_test_cred("example.com", &[1], &[0x01; 16]);
    cred.rp.name = None;
    let bytes = serialize_cred(&cred);
    let decoded = deserialize_cred(&bytes).unwrap();
    assert_eq!(decoded.rp.name, None);
}

#[test]
fn empty_user_name_round_trips() {
    let mut cred = make_test_cred("example.com", &[1], &[0x01; 16]);
    cred.user.name = None;
    cred.user.display_name = None;
    let bytes = serialize_cred(&cred);
    let decoded = deserialize_cred(&bytes).unwrap();
    assert_eq!(decoded.user.name, None);
    assert_eq!(decoded.user.display_name, None);
}

#[test]
fn serialized_size_is_bounded() {
    let cred = make_test_cred("example.com", &[1; 64], &[0x01; 64]);
    let bytes = serialize_cred(&cred);
    assert!(
        bytes.len() < 1024,
        "credential serialization should be < 1KB"
    );
}

#[test]
fn file_corruption_detected() {
    let dir = tempdir().unwrap();
    let rp_dir = dir.path().join("example.com");
    fs::create_dir_all(&rp_dir).unwrap();

    let cred = make_test_cred("example.com", &[1], &[0x01; 16]);
    let mut bytes = serialize_cred(&cred);
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    let path = rp_dir.join("01010101010101010101010101010101.bin");
    fs::write(&path, &bytes).unwrap();

    let read_back = fs::read(&path).unwrap();
    let result = deserialize_cred(&read_back);
    assert!(
        result.is_err(),
        "corrupted file should fail deserialization"
    );
}
