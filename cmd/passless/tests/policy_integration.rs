// Agent-only integration tests.
#![cfg(feature = "agent")]

use passless_core::agent::{CredentialRef, Policy, PolicyError, PolicyParams, ProfileId};

fn base_params() -> PolicyParams {
    PolicyParams {
        profile_id: ProfileId::new("testprofile").unwrap(),
        mode: "isolated".to_string(),
        normalized_rp_ids: vec!["example.com".into()],
        credential_refs: vec![],
        allowed_actions: vec!["authenticate".into()],
        registration_allowed: false,
        require_uv: true,
        max_concurrent_grants: 1,
        max_grant_ttl: 3600,
        max_session_ttl: 7200,
        principal_user: "testuser".into(),
        device_name: "agent-device".into(),
        device_phys: "agent-phys".into(),
        device_uniq: "agent-uniq".into(),
        device_vendor_id: 0x9999,
        device_product_id: 0x0001,
        start_url: None,
        browser_argv: vec![],
        storage_backend: "local".into(),
        storage_path: "/tmp/test".into(),
        browser_user: "browseruser".into(),
        browser_runtime_root: "/tmp/browser".into(),
        rules: vec![],
        delegated_registration_storage: String::new(),
    }
}

#[test]
fn policy_from_params_round_trip() {
    let params = base_params();
    let policy = Policy::from_params(params.clone()).unwrap();
    assert_eq!(policy.version, 3);
    assert_eq!(policy.profile_id, "testprofile");
    assert_eq!(policy.mode, "isolated");
    assert_eq!(policy.normalized_rp_ids, vec!["example.com"]);
    assert_eq!(policy.allowed_actions, vec!["authenticate"]);
}

#[test]
fn policy_sorts_and_deduplicates_rp_ids() {
    let mut params = base_params();
    params.normalized_rp_ids = vec![
        "z.com".into(),
        "a.com".into(),
        "z.com".into(),
        "m.com".into(),
    ];
    let policy = Policy::from_params(params).unwrap();
    assert_eq!(policy.normalized_rp_ids, vec!["a.com", "m.com", "z.com"]);
}

#[test]
fn policy_sorts_and_deduplicates_actions() {
    let mut params = base_params();
    params.allowed_actions = vec![
        "authenticate".into(),
        "register".into(),
        "authenticate".into(),
    ];
    let policy = Policy::from_params(params).unwrap();
    assert_eq!(policy.allowed_actions, vec!["authenticate", "register"]);
}

#[test]
fn policy_sorts_and_deduplicates_credential_refs() {
    let mut params = base_params();
    let ref1 = CredentialRef::from_hex(&"aa".repeat(32)).unwrap();
    let ref2 = CredentialRef::from_hex(&"bb".repeat(32)).unwrap();
    params.credential_refs = vec![ref2.clone(), ref1.clone(), ref2.clone()];
    let policy = Policy::from_params(params).unwrap();
    assert_eq!(policy.credential_refs.len(), 2);
    assert!(policy.credential_refs[0] < policy.credential_refs[1]);
}

#[test]
fn policy_rejects_empty_actions() {
    let mut params = base_params();
    params.allowed_actions = vec![];
    let err = Policy::from_params(params).unwrap_err();
    assert!(matches!(err, PolicyError::EmptyActions));
}

#[test]
fn policy_rejects_zero_grant_ttl() {
    let mut params = base_params();
    params.max_grant_ttl = 0;
    let err = Policy::from_params(params).unwrap_err();
    assert!(matches!(err, PolicyError::InvalidTtl(0)));
}

#[test]
fn policy_rejects_excessive_grant_ttl() {
    let mut params = base_params();
    params.max_grant_ttl = 86400 * 365 + 1;
    let err = Policy::from_params(params).unwrap_err();
    assert!(matches!(err, PolicyError::InvalidTtl(_)));
}

#[test]
fn policy_rejects_zero_concurrent_grants() {
    let mut params = base_params();
    params.max_concurrent_grants = 0;
    let err = Policy::from_params(params).unwrap_err();
    assert!(matches!(err, PolicyError::InvalidMaxConcurrent(0)));
}

#[test]
fn policy_rejects_excessive_concurrent_grants() {
    let mut params = base_params();
    params.max_concurrent_grants = 1001;
    let err = Policy::from_params(params).unwrap_err();
    assert!(matches!(err, PolicyError::InvalidMaxConcurrent(1001)));
}

#[test]
fn policy_new_constructor_validates() {
    let pid = ProfileId::new("test").unwrap();
    let policy = Policy::new(&pid, vec!["authenticate".into()], 1, true, 3600).unwrap();
    assert_eq!(policy.max_concurrent_grants, 1);
    assert!(policy.require_uv);
}

#[test]
fn policy_new_with_empty_actions_fails() {
    let pid = ProfileId::new("test").unwrap();
    let err = Policy::new(&pid, vec![], 1, true, 3600).unwrap_err();
    assert!(matches!(err, PolicyError::EmptyActions));
}

#[test]
fn policy_digest_is_deterministic() {
    let params = base_params();
    let p1 = Policy::from_params(params.clone()).unwrap();
    let p2 = Policy::from_params(params).unwrap();
    assert_eq!(p1.digest(), p2.digest());
}

#[test]
fn policy_digest_changes_when_rp_ids_change() {
    let p1 = Policy::from_params(base_params()).unwrap();
    let mut params2 = base_params();
    params2.normalized_rp_ids = vec!["other.com".into()];
    let p2 = Policy::from_params(params2).unwrap();
    assert_ne!(p1.digest(), p2.digest());
}

#[test]
fn policy_digest_changes_when_actions_change() {
    let p1 = Policy::from_params(base_params()).unwrap();
    let mut params2 = base_params();
    params2.allowed_actions = vec!["register".into()];
    let p2 = Policy::from_params(params2).unwrap();
    assert_ne!(p1.digest(), p2.digest());
}

#[test]
fn policy_digest_changes_when_device_changes() {
    let p1 = Policy::from_params(base_params()).unwrap();
    let mut params2 = base_params();
    params2.device_vendor_id = 0x1234;
    let p2 = Policy::from_params(params2).unwrap();
    assert_ne!(p1.digest(), p2.digest());
}

#[test]
fn policy_cbor_round_trip_preserves_digest() {
    let policy = Policy::from_params(base_params()).unwrap();
    let cbor_bytes = policy.to_deterministic_cbor();
    assert!(!cbor_bytes.is_empty());

    let digest_before = policy.digest();
    let decoded: Policy = serde_json::from_slice(&serde_json::to_vec(&policy).unwrap()).unwrap();
    assert_eq!(decoded.digest(), digest_before);
}

#[test]
fn policy_cbor_is_deterministic_across_calls() {
    let policy = Policy::from_params(base_params()).unwrap();
    let cbor1 = policy.to_deterministic_cbor();
    let cbor2 = policy.to_deterministic_cbor();
    assert_eq!(cbor1, cbor2);
}

#[test]
fn policy_digest_hex_format_is_valid() {
    let policy = Policy::from_params(base_params()).unwrap();
    let digest = policy.digest();
    let hex_str = digest.to_hex();
    assert_eq!(hex_str.len(), 64);
    assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn policy_start_url_default_empty_when_none() {
    let params = base_params();
    let policy = Policy::from_params(params).unwrap();
    assert_eq!(policy.start_url, "");
}

#[test]
fn policy_start_url_preserved_when_set() {
    let mut params = base_params();
    params.start_url = Some("https://example.com/auth".into());
    let policy = Policy::from_params(params).unwrap();
    assert_eq!(policy.start_url, "https://example.com/auth");
}

#[test]
fn policy_validate_rejects_wrong_version() {
    let mut policy = Policy::from_params(base_params()).unwrap();
    policy.version = 99;
    let err = policy.validate().unwrap_err();
    assert!(matches!(err, PolicyError::InvalidVersion(99)));
}

#[test]
fn policy_error_display_messages() {
    assert!(
        PolicyError::EmptyActions
            .to_string()
            .contains("allowed_actions")
    );
    assert!(PolicyError::InvalidTtl(0).to_string().contains("TTL"));
    assert!(
        PolicyError::InvalidMaxConcurrent(0)
            .to_string()
            .contains("max_concurrent")
    );
}
