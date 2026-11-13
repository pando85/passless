// Agent-only integration tests.
#![cfg(feature = "agent")]

use std::collections::BTreeMap;
use std::path::PathBuf;

use passless_core::agent::{
    AgentConfig, AgentMode, AgentProfileConfig, AgentRpRule, AgentStorageConfig, BoundedDuration,
    BrowserScope, RuleAction, validate_rp_id,
};

fn isolated_profile() -> AgentProfileConfig {
    AgentProfileConfig {
        max_wildcard_registrations: None,
        wildcard_registration_prompts_per_day: None,
        pre_request_actions: Vec::new(),
        max_granted_rules: 64,
        max_operations: 64,
        max_concurrent_sessions: 1,
        browser_scope: BrowserScope::Session,
        credential_selection: passless_core::agent::config::CredentialSelection::Single,
        mode: AgentMode::Isolated,
        principal_user: "testuser".into(),
        credential_refs: None,
        max_grant_ttl: None,
        max_session_ttl: None,
        storage: Some(AgentStorageConfig::Local {
            path: PathBuf::from("/tmp/agent-test/cred"),
            pin_path: PathBuf::from("/tmp/agent-test/pin"),
        }),
        rules: vec![AgentRpRule {
            rp_id: "example.com".into(),
            register: RuleAction::Deny,
            authenticate: RuleAction::Allow,
            credential_selection: None,
        }],
        legacy: Default::default(),
        device: None,
        start_url: None,
        browser_command: None,
        browser_user: None,
        browser_runtime_root: None,
        browser_cdp_expose: None,
        browser_cdp_port: None,
    }
}

#[test]
fn max_concurrent_sessions_zero_rejected() {
    let mut profile = isolated_profile();
    profile.max_concurrent_sessions = 0;
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("max_concurrent_sessions"));
}

#[test]
fn concurrent_port_mode_rejects_fixed_cdp_port() {
    let mut profile = isolated_profile();
    profile.max_concurrent_sessions = 2;
    profile.browser_cdp_expose = Some(passless_core::agent::config::CdpExposeMode::Port);
    profile.browser_cdp_port = Some(9222);
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("browser_cdp_port must be 0"));
}

#[test]
fn concurrent_port_mode_accepts_ephemeral_cdp_port() {
    let mut profile = isolated_profile();
    profile.max_concurrent_sessions = 2;
    profile.browser_cdp_expose = Some(passless_core::agent::config::CdpExposeMode::Port);
    profile.browser_cdp_port = Some(0);
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    assert!(profile.validate(&pid).is_ok());
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

/// Defect B7: an isolated profile may set `browser_runtime_root` (it only says where the
/// browser's per-lease directories live), and the setting survives a TOML round trip.
#[test]
fn isolated_mode_accepts_browser_runtime_root() {
    let mut profile = isolated_profile();
    profile.browser_runtime_root = Some(PathBuf::from("/tmp/x"));
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    profile.validate(&pid).unwrap();

    let toml = r#"
        enabled = true
        [profiles.iso]
        mode = "isolated"
        principal_user = "agent"
        browser_runtime_root = "/run/passless-agent/iso"
        [profiles.iso.storage.local]
        path = "/tmp/iso/credentials"
        pin_path = "/tmp/iso/pin"
        [[profiles.iso.rules]]
        rp_id = "example.com"
        authenticate = "allow"
        register = "deny"
    "#;
    let config: passless_core::agent::AgentConfig = toml::from_str(toml).unwrap();
    let iso = &config.profiles["iso"];
    iso.validate(&pid).unwrap();
    assert_eq!(
        iso.browser_runtime_root,
        Some(PathBuf::from("/run/passless-agent/iso"))
    );
}

#[test]
fn invalid_rp_id_in_profile_rejected() {
    let mut profile = isolated_profile();
    profile.rules[0].rp_id = "https://example.com".into();
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    let err = profile.validate(&pid).unwrap_err();
    assert!(err.to_string().contains("scheme"));
}

#[test]
fn agent_config_disabled_skips_validation() {
    let config = AgentConfig {
        acknowledge_global_registration: vec![],
        notify_user: None,
        state_dir: None,
        escalation_timeout: None,
        escalation_cooldown: 600,
        allow_automatic_human_path: false,
        browser_path: None,
        limits: Default::default(),
        enabled: false,
        profiles: BTreeMap::new(),
        audit_path: None,
        acknowledge_global_same_user: vec![],
        acknowledge_same_user_registration: vec![],
    };
    assert!(config.validate(None).is_ok());
}

#[test]
fn agent_config_enabled_requires_audit_path() {
    let config = AgentConfig {
        acknowledge_global_registration: vec![],
        notify_user: None,
        state_dir: None,
        escalation_timeout: None,
        escalation_cooldown: 600,
        allow_automatic_human_path: false,
        browser_path: None,
        limits: Default::default(),
        enabled: true,
        profiles: BTreeMap::new(),
        audit_path: None,
        acknowledge_global_same_user: vec![],
        acknowledge_same_user_registration: vec![],
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
    profiles.insert("p1".to_string(), p1);

    let mut p2 = isolated_profile();
    p2.storage = Some(AgentStorageConfig::Local {
        path: PathBuf::from("/tmp/agent-overlap/cred/sub"),
        pin_path: PathBuf::from("/tmp/agent-overlap/pin2"),
    });
    profiles.insert("p2".to_string(), p2);

    let config = AgentConfig {
        acknowledge_global_registration: vec![],
        notify_user: None,
        state_dir: None,
        escalation_timeout: None,
        escalation_cooldown: 600,
        allow_automatic_human_path: false,
        browser_path: None,
        limits: Default::default(),
        enabled: true,
        profiles,
        audit_path: Some(PathBuf::from("/tmp/agent-overlap/audit")),
        acknowledge_global_same_user: vec![],
        acknowledge_same_user_registration: vec![],
    };
    let err = config.validate(None).unwrap_err();
    assert!(err.to_string().contains("overlap"));
}

// B6 regression: profiles no longer need a distinct `[device]` identity (agents have no UHID route),
// and a legacy `[device]` key is accepted and ignored.
#[test]
fn agent_config_accepts_profiles_sharing_a_legacy_device_identity() {
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
        acknowledge_global_registration: vec![],
        notify_user: None,
        state_dir: None,
        escalation_timeout: None,
        escalation_cooldown: 600,
        allow_automatic_human_path: false,
        browser_path: None,
        limits: Default::default(),
        enabled: true,
        profiles,
        audit_path: Some(PathBuf::from("/tmp/collision-test/audit")),
        acknowledge_global_same_user: vec![],
        acknowledge_same_user_registration: vec![],
    };
    config.validate(None).unwrap();
}

#[test]
fn legacy_device_table_is_parsed_and_ignored() {
    let mut profile = isolated_profile();
    profile.device = Some(passless_core::agent::DeviceIdentity::default());
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    assert_eq!(profile.deprecation_warnings(&pid).len(), 1);
    profile.validate(&pid).unwrap();
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
        acknowledge_global_registration: vec![],
        notify_user: None,
        state_dir: None,
        escalation_timeout: None,
        escalation_cooldown: 600,
        allow_automatic_human_path: false,
        browser_path: None,
        limits: Default::default(),
        enabled: true,
        profiles,
        audit_path: Some(PathBuf::from("/tmp/human-overlap/audit")),
        acknowledge_global_same_user: vec![],
        acknowledge_same_user_registration: vec![],
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
    // `localhost` is the one exception to the public-suffix rule; its subdomains stay invalid.
    assert_eq!(validate_rp_id("localhost").unwrap(), "localhost");
    assert!(validate_rp_id("foo.localhost").is_err());
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
        git_sync: true,
        git_auto_push: true,
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
        git_sync: true,
        git_auto_push: true,
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

// B4 regression: a profile whose rules are all `deny` is valid.
#[test]
fn all_deny_rule_set_validates() {
    let mut profile = isolated_profile();
    profile.rules[0].authenticate = RuleAction::Deny;
    profile.rules[0].register = RuleAction::Deny;
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    profile.validate(&pid).unwrap();
}

#[test]
fn profile_without_rules_validates_and_denies_everything() {
    let mut profile = isolated_profile();
    profile.rules.clear();
    let pid = passless_core::agent::ProfileId::new("test").unwrap();
    profile.validate(&pid).unwrap();
}
