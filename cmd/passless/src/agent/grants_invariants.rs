//! Invariant tests of the granted-rules store that sit across its API (ADR 0014 sections 8.4 and
//! 14, invariant 12): the operator's configuration file is never written by the daemon, and the
//! store's own `grants_digest` identifies its content.

use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use passless_core::agent::{AgentConfig, ProfileId};

use super::browser::SystemClock;
use super::granted_rules::{
    GrantKind, GrantedAction, GrantedRule, GrantedRulesStore, PermittingRule,
};
use super::policy_engine::PolicyRuntime;

const CONFIG: &str = r#"
[agents]
enabled = true
audit_path = "/nonexistent/audit"

[agents.profiles.agent]
mode = "same-user"
principal_user = "alice"

[[agents.profiles.agent.rules]]
rp_id = "example.com"
authenticate = "request"
register = "deny"

[[agents.profiles.agent.rules]]
rp_id = "other.example"
authenticate = "request"
register = "deny"
"#;

fn profile() -> ProfileId {
    ProfileId::new("agent").unwrap()
}

fn config() -> AgentConfig {
    AgentConfig::from_toml_str(CONFIG, "test").unwrap()
}

fn policy() -> PolicyRuntime {
    PolicyRuntime::new(&config(), Arc::new(SystemClock), None).unwrap()
}

fn grant(rp_id: &str) -> GrantedRule {
    GrantedRule::new(
        rp_id,
        GrantKind::Escalation,
        &format!("esc-{rp_id}"),
        &format!("https://{rp_id}"),
        PermittingRule::Exact,
        None,
    )
}

#[test]
fn the_daemon_never_writes_the_operator_config() {
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    fs::write(&config_path, CONFIG).unwrap();
    // An old mtime, so that any rewrite (even with identical bytes) moves it.
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    fs::File::options()
        .write(true)
        .open(&config_path)
        .unwrap()
        .set_modified(old)
        .unwrap();
    let before_meta = fs::metadata(&config_path).unwrap();
    let before_bytes = fs::read(&config_path).unwrap();

    // The state directory sits next to the config on purpose: a stray write would land here.
    let state_dir = root.path().join("state");
    let store = GrantedRulesStore::open(&state_dir, [profile()]);
    let policy = policy();

    // Approve (add), re-approve, revoke, approve again, clear, approve, compensate.
    store
        .add(&policy, &profile(), grant("example.com"), 8)
        .unwrap();
    store
        .add(&policy, &profile(), grant("other.example"), 8)
        .unwrap();
    store
        .revoke(
            &policy,
            &profile(),
            "example.com",
            GrantedAction::Authenticate,
        )
        .unwrap();
    store
        .add(&policy, &profile(), grant("example.com"), 8)
        .unwrap();
    store.clear(&policy, &profile()).unwrap();
    store
        .add(&policy, &profile(), grant("example.com"), 8)
        .unwrap();
    store
        .revoke_request(&policy, &profile(), "esc-example.com")
        .unwrap();
    // A reload from the same file's content reads it and writes nothing back.
    let reloaded =
        AgentConfig::from_toml_str(&fs::read_to_string(&config_path).unwrap(), "test").unwrap();
    policy_reload(&policy, &reloaded);

    let after_meta = fs::metadata(&config_path).unwrap();
    assert_eq!(fs::read(&config_path).unwrap(), before_bytes, "contents");
    assert_eq!(after_meta.modified().unwrap(), old, "mtime");
    assert_eq!(after_meta.len(), before_meta.len());
    let mut entries: Vec<_> = fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        ["config.toml", "state"],
        "nothing else is written next to the config"
    );
}

fn policy_reload(policy: &PolicyRuntime, config: &AgentConfig) {
    policy.reload(config).unwrap();
}

#[test]
fn the_grants_digest_is_stable_for_the_same_set_and_changes_on_add_and_revoke() {
    let root = tempfile::tempdir().unwrap();
    let store = GrantedRulesStore::open(root.path(), [profile()]);
    let policy = policy();
    let digest = |store: &GrantedRulesStore| store.grants_digest(&profile()).unwrap();

    let empty = digest(&store);
    assert_eq!(empty, digest(&store), "reading does not change it");
    assert_eq!(empty.len(), 64, "a hex SHA-256: {empty}");

    store
        .add(&policy, &profile(), grant("example.com"), 8)
        .unwrap();
    let one = digest(&store);
    assert_ne!(one, empty, "an add changes it");

    store
        .add(&policy, &profile(), grant("other.example"), 8)
        .unwrap();
    let two = digest(&store);
    assert_ne!(two, one);

    // The same set reloaded from disk has the same digest.
    let reopened = GrantedRulesStore::open(root.path(), [profile()]);
    assert_eq!(digest(&reopened), two, "stable for the same set");

    // A revoke changes it, back to the digest of the remaining set.
    store
        .revoke(
            &policy,
            &profile(),
            "other.example",
            GrantedAction::Authenticate,
        )
        .unwrap();
    assert_eq!(digest(&store), one, "the remaining set has its own digest");
    store.clear(&policy, &profile()).unwrap();
    assert_eq!(digest(&store), empty);

    // An unknown profile has no digest.
    assert!(
        store
            .grants_digest(&ProfileId::new("nobody").unwrap())
            .is_none()
    );
}

#[test]
fn the_grants_digest_is_not_the_policy_digest_and_the_policy_digest_ignores_grants() {
    let root = tempfile::tempdir().unwrap();
    let store = GrantedRulesStore::open(root.path(), [profile()]);
    let policy = policy();
    let policy_digest = policy.digest();
    let grants_before = store.grants_digest(&profile()).unwrap();

    store
        .add(&policy, &profile(), grant("example.com"), 8)
        .unwrap();

    // Invariant 12 / ADR 8.4: the policy digest excludes the store, which has its own digest.
    assert_eq!(
        policy.digest(),
        policy_digest,
        "grants are not in the policy digest"
    );
    assert_ne!(store.grants_digest(&profile()).unwrap(), grants_before);
    // A configuration reload does not move the grants digest either.
    let grants_after = store.grants_digest(&profile()).unwrap();
    policy_reload(&policy, &config());
    assert_eq!(store.grants_digest(&profile()).unwrap(), grants_after);
}
