// Agent-only integration tests.
#![cfg(feature = "agent")]

use passless_core::agent::{
    AdminRequest, AdminRequestFrame, AdminResponse, AdminResponseFrame, CodecError, CredentialRef,
    ErrorCode, MAX_MESSAGE_SIZE, PrincipalCapabilityProof, PrincipalRequest, PrincipalRequestFrame,
    PrincipalResponse, PrincipalResponseFrame, ProtocolError, ProtocolVersion, RecommendedAction,
    RequestFrame, ResponseFrame, Role, SeqpacketCodec, Validate,
};

use passless_core::agent::{IntentAction, PrincipalSessionId, ProfileId};

fn valid_proof() -> PrincipalCapabilityProof {
    PrincipalCapabilityProof::from_bytes([0xAB; 32])
}

fn valid_profile_id() -> ProfileId {
    ProfileId::new("testprofile").unwrap()
}

fn valid_credential_ref() -> CredentialRef {
    CredentialRef::from_hex(&"aa".repeat(32)).unwrap()
}

fn valid_session_id() -> PrincipalSessionId {
    "cc".repeat(32).parse().unwrap()
}

#[test]
fn version_negotiation_accepts_current_major() {
    let offer = ProtocolVersion::new(1, 0);
    let negotiated = ProtocolVersion::negotiate(offer).unwrap();
    assert_eq!(negotiated, ProtocolVersion::new(1, 0));
}

#[test]
fn version_negotiation_accepts_higher_minor() {
    let offer = ProtocolVersion::new(1, 99);
    let negotiated = ProtocolVersion::negotiate(offer).unwrap();
    assert_eq!(negotiated.minor, 2);
}

#[test]
fn version_negotiation_rejects_zero_major() {
    let offer = ProtocolVersion::new(0, 5);
    let err = ProtocolVersion::negotiate(offer).unwrap_err();
    assert_eq!(err.code, ErrorCode::VersionMismatch);
}

#[test]
fn version_negotiation_rejects_different_major() {
    let offer = ProtocolVersion::new(2, 0);
    let err = ProtocolVersion::negotiate(offer).unwrap_err();
    assert_eq!(err.code, ErrorCode::VersionMismatch);
    assert_eq!(err.recommended_action, RecommendedAction::UpgradeClient);
}

#[test]
fn admin_ping_round_trip_through_codec() {
    let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
    let encoded = SeqpacketCodec::encode(&frame).unwrap();
    let decoded: RequestFrame = SeqpacketCodec::decode(&encoded).unwrap();
    assert_eq!(decoded.role(), Role::Admin);
    assert_eq!(decoded.seq(), 1);
}

#[test]
fn principal_frame_round_trip_through_codec() {
    let action = PrincipalRequest::CreateIntent {
        profile_id: valid_profile_id(),
        action: IntentAction::Register,
        rp_id: "example.com".into(),
        credential_ref: None,
        reason: None,
        grant_ttl_secs: None,
        session_ttl_secs: None,
    };
    let frame = RequestFrame::Principal(PrincipalRequestFrame::new(42, action, valid_proof()));
    let encoded = SeqpacketCodec::encode(&frame).unwrap();
    let decoded: RequestFrame = SeqpacketCodec::decode(&encoded).unwrap();
    assert_eq!(decoded.role(), Role::Principal);
    assert_eq!(decoded.seq(), 42);
}

#[test]
fn admin_response_ok_frame_round_trip() {
    let frame = ResponseFrame::Admin(AdminResponseFrame::ok(7, AdminResponse::Pong));
    let encoded = SeqpacketCodec::encode(&frame).unwrap();
    let decoded: ResponseFrame = SeqpacketCodec::decode(&encoded).unwrap();
    assert!(decoded.is_ok());
    assert_eq!(decoded.role(), Role::Admin);
    assert_eq!(decoded.seq(), 7);
}

#[test]
fn admin_response_error_frame_round_trip() {
    let err = ProtocolError::new(ErrorCode::Forbidden, "nope", RecommendedAction::Abort);
    let frame = ResponseFrame::Admin(AdminResponseFrame::error(3, err));
    let encoded = SeqpacketCodec::encode(&frame).unwrap();
    let decoded: ResponseFrame = SeqpacketCodec::decode(&encoded).unwrap();
    assert!(!decoded.is_ok());
}

#[test]
fn oversized_message_is_rejected_by_encode() {
    let big_string = "x".repeat(MAX_MESSAGE_SIZE + 1);
    let action = AdminRequest::LaunchPrincipal {
        profile_id: valid_profile_id(),
        command: vec![big_string],
    };
    let frame = RequestFrame::Admin(AdminRequestFrame::new(1, action));
    let result = SeqpacketCodec::encode(&frame);
    assert!(result.is_err());
    match result.unwrap_err() {
        CodecError::Oversized { size, max } => {
            assert!(size > MAX_MESSAGE_SIZE);
            assert_eq!(max, MAX_MESSAGE_SIZE);
        }
        other => panic!("expected Oversized, got: {:?}", other),
    }
}

#[test]
fn oversized_buffer_is_rejected_by_decode() {
    let big_buf = vec![0u8; MAX_MESSAGE_SIZE + 1];
    let result: Result<RequestFrame, _> = SeqpacketCodec::decode(&big_buf);
    assert!(result.is_err());
}

#[test]
fn truncated_garbage_is_rejected_by_decode() {
    let result: Result<RequestFrame, _> = SeqpacketCodec::decode(b"not json at all");
    assert!(result.is_err());
}

#[test]
fn empty_buffer_is_rejected_by_decode() {
    let result: Result<RequestFrame, _> = SeqpacketCodec::decode(b"");
    assert!(result.is_err());
}

#[test]
fn unknown_field_in_admin_request_is_rejected() {
    let json = r#"{"role":"admin","v":{"major":1,"minor":0},"seq":1,"action":{"ping_extra":true}}"#;
    let result: Result<RequestFrame, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn unknown_field_in_principal_request_is_rejected() {
    let json = format!(
        r#"{{"role":"principal","v":{{"major":1,"minor":0}},"seq":1,"action":{{"unknown_action":true}},"capability_proof":"{}"}}"#,
        "ab".repeat(32)
    );
    let result: Result<RequestFrame, _> = serde_json::from_str(&json);
    assert!(result.is_err());
}

#[test]
fn admin_validate_ping_succeeds() {
    let req = AdminRequest::Ping;
    assert!(req.validate().is_ok());
}

#[test]
fn admin_validate_launch_principal_empty_command() {
    let req = AdminRequest::LaunchPrincipal {
        profile_id: valid_profile_id(),
        command: vec![],
    };
    let errors = req.validate().unwrap_err();
    assert!(!errors.is_empty());
    assert!(
        errors
            .0
            .iter()
            .any(|e| e.contains("command must not be empty"))
    );
}

#[test]
fn admin_validate_launch_principal_null_in_argv() {
    let req = AdminRequest::LaunchPrincipal {
        profile_id: valid_profile_id(),
        command: vec!["/bin/true".into(), "arg\0with\0nulls".into()],
    };
    let errors = req.validate().unwrap_err();
    assert!(errors.0.iter().any(|e| e.contains("null bytes")));
}

#[test]
fn admin_validate_rename_requires_at_least_one_name() {
    let req = AdminRequest::RenameCredential {
        credential_ref: valid_credential_ref(),
        user_name: None,
        display_name: None,
    };
    let errors = req.validate().unwrap_err();
    assert!(errors.0.iter().any(|e| e.contains("at least one")));
}

#[test]
fn admin_validate_wait_principal_timeout_capped() {
    let req = AdminRequest::WaitPrincipal {
        session_id: valid_session_id(),
        timeout_ms: 99999,
    };
    let errors = req.validate().unwrap_err();
    assert!(errors.0.iter().any(|e| e.contains("timeout_ms")));
}

#[test]
fn principal_validate_create_intent_valid() {
    let req = PrincipalRequest::CreateIntent {
        profile_id: valid_profile_id(),
        action: IntentAction::Authenticate,
        rp_id: "example.com".into(),
        credential_ref: None,
        reason: Some("testing".into()),
        grant_ttl_secs: None,
        session_ttl_secs: None,
    };
    assert!(req.validate().is_ok());
}

#[test]
fn principal_validate_browser_control_empty_json() {
    let req = PrincipalRequest::BrowserControl {
        request_json: "".into(),
        timeout_ms: 1000,
    };
    let errors = req.validate().unwrap_err();
    assert!(
        errors
            .0
            .iter()
            .any(|e| e.contains("request_json must not be empty"))
    );
}

#[test]
fn principal_validate_browser_control_timeout_zero() {
    let req = PrincipalRequest::BrowserControl {
        request_json: r#"{"id":1}"#.into(),
        timeout_ms: 0,
    };
    let errors = req.validate().unwrap_err();
    assert!(errors.0.iter().any(|e| e.contains("timeout_ms")));
}

#[test]
fn principal_validate_browser_control_null_in_json() {
    let req = PrincipalRequest::BrowserControl {
        request_json: "null\0byte".into(),
        timeout_ms: 1000,
    };
    let errors = req.validate().unwrap_err();
    assert!(errors.0.iter().any(|e| e.contains("null bytes")));
}

#[test]
fn request_frame_validate_checks_version_and_action() {
    let bad_version_frame = RequestFrame::Admin(AdminRequestFrame {
        v: ProtocolVersion::new(0, 0),
        seq: 1,
        action: AdminRequest::Ping,
    });
    let errors = bad_version_frame.validate().unwrap_err();
    assert!(errors.0.iter().any(|e| e.contains("major version")));
}

#[test]
fn role_separation_admin_vs_principal() {
    let admin = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Status));
    let principal = RequestFrame::Principal(PrincipalRequestFrame::new(
        2,
        PrincipalRequest::Ping,
        valid_proof(),
    ));
    assert_eq!(admin.role(), Role::Admin);
    assert_eq!(principal.role(), Role::Principal);
    assert_ne!(admin.role(), principal.role());
}

#[test]
fn response_frame_role_matches_request_role() {
    let admin_resp = ResponseFrame::Admin(AdminResponseFrame::ok(1, AdminResponse::Pong));
    let principal_resp =
        ResponseFrame::Principal(PrincipalResponseFrame::ok(1, PrincipalResponse::Pong));
    assert_eq!(admin_resp.role(), Role::Admin);
    assert_eq!(principal_resp.role(), Role::Principal);
}

#[test]
fn protocol_error_constructors_produce_correct_codes() {
    let malformed = ProtocolError::malformed("bad");
    assert_eq!(malformed.code, ErrorCode::MalformedMessage);
    assert_eq!(malformed.recommended_action, RecommendedAction::FixRequest);

    let oversized = ProtocolError::oversized(99999, MAX_MESSAGE_SIZE);
    assert_eq!(oversized.code, ErrorCode::MessageTooLarge);

    let mismatch = ProtocolError::version_mismatch(&ProtocolVersion::new(9, 0));
    assert_eq!(mismatch.code, ErrorCode::VersionMismatch);
    assert_eq!(
        mismatch.recommended_action,
        RecommendedAction::UpgradeClient
    );
}

#[test]
fn principal_capability_proof_constant_time_verify() {
    let a = PrincipalCapabilityProof::from_bytes([0x11; 32]);
    let b = PrincipalCapabilityProof::from_bytes([0x11; 32]);
    let c = PrincipalCapabilityProof::from_bytes([0x22; 32]);
    assert!(a.verify_constant_time(&b));
    assert!(!a.verify_constant_time(&c));
}

#[test]
fn principal_capability_proof_debug_does_not_leak() {
    let proof = PrincipalCapabilityProof::from_bytes([0xAB; 32]);
    let debug = format!("{:?}", proof);
    let display = format!("{}", proof);
    assert!(
        !debug.contains("abababab"),
        "debug should not contain hex bytes"
    );
    assert!(display.contains("***"));
}

#[test]
fn admin_request_deny_unknown_fields_via_serde() {
    let json = r#"{"list_credentials": {"rp_id": "example.com", "extra_field": true}}"#;
    let result: Result<AdminRequest, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn principal_response_deny_unknown_fields_via_serde() {
    let json = r#"{"pong": true, "extra": 1}"#;
    let result: Result<PrincipalResponse, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn max_boundary_message_size_succeeds() {
    let action = AdminRequest::Ping;
    let frame = RequestFrame::Admin(AdminRequestFrame::new(1, action));
    let encoded = SeqpacketCodec::encode(&frame).unwrap();
    assert!(encoded.len() <= MAX_MESSAGE_SIZE);
    let _: RequestFrame = SeqpacketCodec::decode(&encoded).unwrap();
}
