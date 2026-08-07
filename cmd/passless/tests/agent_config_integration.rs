// Agent-only integration tests.
#![cfg(feature = "agent")]

use std::collections::BTreeMap;
use std::path::PathBuf;

use passless_core::agent::{
    AgentConfig, AgentMode, AgentProfileConfig, AgentStorageConfig, BoundedDuration,
    DeviceIdentity, validate_rp_id,
};

fn minimal_device() -> DeviceIdentity {
    DeviceIdentity {
        name: "agent-test-dev".into(),
        phys: "agent-test-phys".into(),
        uniq: "agent-test-uniq".into(),
        vendor_id: 0x9999,
        product_id: 0x0001,
    }
}

fn isolated_profile() -> AgentProfileConfig {
    AgentProfileConfig {
        max_operations: 64,
        credential_selection: passless_core::agent::config::CredentialSelection::Single,
        human_verification_prompt: passless_core::agent::config::HumanVerificationPrompt::Always,
        mode: AgentMode::Isolated,
        principal_user: "testuser".into(),
        rp_ids: vec!["example.com".into()],
        require_uv: true,
        credential_refs: None,
        max_grant_ttl: None,
        max_session_ttl: None,
        storage: Some(AgentStorageConfig::Local {
            path: PathBuf::from("/tmp/agent-test/cred"),
            pin_path: PathBuf::from("/tmp/agent-test/pin"),
        }),
        registration_allowed: false,
        rules: vec![],
        device: minimal_device(),
        start_url: None,
        browser_command: None,
        browser_user: None,
        browser_runtime_root: None,
        browser_cdp_expose: None,
        browser_cdp_port: None,
    }
}

#[test]
fn isolated_profile_validates_successfully() {
    let profile = isolated_profile();
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    assert!(profile.validate(&pid).is_ok());
}

#[test]
fn empty_principal_user_rejected() {
    let mut profile = isolated_profile();
    profile.principal_user = "".into();
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("principal_user"));
}

#[test]
fn isolated_mode_requires_storage() {
    let mut profile = isolated_profile();
    profile.storage = None;
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("storage"));
}

#[test]
fn isolated_mode_rejects_browser_user() {
    let mut profile = isolated_profile();
    profile.browser_user = Some("someone".into());
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("browser_user"));
}

#[test]
fn isolated_mode_rejects_browser_runtime_root() {
    let mut profile = isolated_profile();
    profile.browser_runtime_root = Some(PathBuf::from("/tmp/x"));
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("browser_runtime_root"));
}

#[test]
fn device_collision_with_human_authenticator_rejected() {
    let mut profile = isolated_profile();
    profile.device = DeviceIdentity {
        name: "virtual-fido".into(),
        phys: "virtual-fido-001".into(),
        uniq: "anything".into(),
        vendor_id: 0x15d9,
        product_id: 0x0a37,
    };
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(
        err.to_string()
            .contains("collides with the human authenticator")
    );
}

#[test]
fn device_name_with_nul_byte_rejected() {
    let mut profile = isolated_profile();
    profile.device.name = "bad\0name".into();
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("NUL"));
}

#[test]
fn device_name_too_long_rejected() {
    let mut profile = isolated_profile();
    profile.device.name = "x".repeat(200);
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("exceeds maximum length"));
}

#[test]
fn invalid_rp_id_in_profile_rejected() {
    let mut profile = isolated_profile();
    profile.rp_ids = vec!["https://example.com".into()];
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("scheme"));
}

#[test]
fn agent_config_disabled_skips_validation() {
    let config = AgentConfig {
        enabled: false,
        profiles: BTreeMap::new(),
        audit_path: None,
    };
    assert!(config.validate(None).is_ok());
}

#[test]
fn agent_config_enabled_requires_audit_path() {
    let config = AgentConfig {
        enabled: true,
        profiles: BTreeMap::new(),
        audit_path: None,
    };
    let err = config.validate(None).unwrap_err();
    assert!(err.to_string().contains("audit_path"));
}

#[test]
fn agent_config_detects_overlapping_storage_paths() {
    let mut profiles = BTreeMap::new();
    let mut p1 = isolated_profile();
    p1.storage = Some(AgentStorageConfig::Local {
        path: PathBuf::from("/tmp/agent-overlap/cred"),
        pin_path: PathBuf::from("/tmp/agent-overlap/pin"),
    });
    p1.device.name = "dev1".into();
    profiles.insert("p1".to_string(), p1);

    let mut p2 = isolated_profile();
    p2.storage = Some(AgentStorageConfig::Local {
        path: PathBuf::from("/tmp/agent-overlap/cred/sub"),
        pin_path: PathBuf::from("/tmp/agent-overlap/pin2"),
    });
    p2.device.name = "dev2".into();
    profiles.insert("p2".to_string(), p2);

    let config = AgentConfig {
        enabled: true,
        profiles,
        audit_path: Some(PathBuf::from("/tmp/agent-overlap/audit")),
    };
    let err = config.validate(None).unwrap_err();
    assert!(err.to_string().contains("overlap"));
}

#[test]
fn agent_config_detects_device_identity_collision() {
    let mut profiles = BTreeMap::new();
    let mut p1 = isolated_profile();
    p1.storage = Some(AgentStorageConfig::Local {
        path: PathBuf::from("/tmp/collision-test/p1/cred"),
        pin_path: PathBuf::from("/tmp/collision-test/p1/pin"),
    });
    profiles.insert("p1".to_string(), p1);

    let mut p2 = isolated_profile();
    p2.storage = Some(AgentStorageConfig::Local {
        path: PathBuf::from("/tmp/collision-test/p2/cred"),
        pin_path: PathBuf::from("/tmp/collision-test/p2/pin"),
    });
    profiles.insert("p2".to_string(), p2);

    let config = AgentConfig {
        enabled: true,
        profiles,
        audit_path: Some(PathBuf::from("/tmp/collision-test/audit")),
    };
    let err = config.validate(None).unwrap_err();
    assert!(err.to_string().contains("device identity collides"));
}

#[test]
fn agent_config_detects_overlap_with_human_backend() {
    let mut profiles = BTreeMap::new();
    let mut p = isolated_profile();
    p.storage = Some(AgentStorageConfig::Local {
        path: PathBuf::from("/tmp/human-overlap/cred"),
        pin_path: PathBuf::from("/tmp/human-overlap/pin"),
    });
    profiles.insert("p".to_string(), p);

    let config = AgentConfig {
        enabled: true,
        profiles,
        audit_path: Some(PathBuf::from("/tmp/human-overlap/audit")),
    };

    let human_path = std::path::Path::new("/tmp/human-overlap");
    let err = config.validate(Some(human_path)).unwrap_err();
    assert!(err.to_string().contains("overlaps with human backend"));
}

#[test]
fn rp_id_validation_integration() {
    assert!(validate_rp_id("example.com").is_ok());
    assert!(validate_rp_id("sub.example.com").is_ok());
    assert!(validate_rp_id("https://example.com").is_err());
    assert!(validate_rp_id("localhost").is_err());
    assert!(validate_rp_id("com").is_err());
    assert!(validate_rp_id("*.example.com").is_err());
    assert!(validate_rp_id("192.168.1.1").is_err());
    assert!(validate_rp_id("").is_err());
}

#[test]
fn bounded_duration_boundaries() {
    assert!(BoundedDuration::new(0).is_err());
    assert!(BoundedDuration::new(1).is_ok());
    assert!(BoundedDuration::new(86_400 * 365).is_ok());
    assert!(BoundedDuration::new(86_400 * 365 + 1).is_err());
}

#[test]
fn pass_storage_pin_path_absolute_rejected() {
    let storage = AgentStorageConfig::Pass {
        store_path: PathBuf::from("/tmp/store"),
        path: "fido2".into(),
        gpg_backend: "gnupg-bin".into(),
        pin_path: PathBuf::from("/absolute/pin"),
    };
    let err = storage.validate().unwrap_err();
    assert!(err.to_string().contains("relative subpath"));
}

#[test]
fn pass_storage_pin_path_traversal_rejected() {
    let storage = AgentStorageConfig::Pass {
        store_path: PathBuf::from("/tmp/store"),
        path: "fido2".into(),
        gpg_backend: "gnupg-bin".into(),
        pin_path: PathBuf::from("../escape"),
    };
    let err = storage.validate().unwrap_err();
    assert!(err.to_string().contains("path traversal"));
}

#[test]
fn empty_start_url_rejected() {
    let mut profile = isolated_profile();
    profile.start_url = Some("".into());
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("start_url must not be empty"));
}
