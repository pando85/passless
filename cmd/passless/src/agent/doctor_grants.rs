//! Orphaned and inert granted rules (ADR 0014 section 6.2).
//!
//! A granted rule only ever upgrades a configured `authenticate = "request"` to `allow` for its
//! exact RP. It does nothing when no rule of the profile reaches the RP, when the reaching rule is
//! now `deny`, or when it is `allow` (the grant is redundant), and nothing remains to consult it
//! when the profile itself is gone from the configuration. None of these is a security problem
//! (resolution never consults an inert grant), but the operator should know, because the entry
//! will silently start working again if the rule goes back to `request`.
//!
//! The checks are pure over the configuration and the loaded store views: `profile check` runs
//! [`inert_grants_check`] on the daemon's live view, `doctor --agents` runs [`run`] offline.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use passless_core::agent::protocol::DoctorCheck;
use passless_core::agent::{
    AgentConfig, AgentProfileConfig, PolicyAction, ProfileId, RuleAction, RuleIdentity,
    resolve_rules,
};

use super::granted_rules::{GRANTED_RULES_DIR, GrantedRule, GrantedRulesStore, ProfileGrants};

/// Why a granted rule does nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InertReason {
    /// No rule of the profile reaches the RP (the rule was removed, or never covered it).
    NoRule,
    /// The reaching rule is `deny`.
    RuleDenies,
    /// The reaching rule is `allow`: the grant is redundant.
    RuleAllows,
}

impl InertReason {
    fn describe(self) -> &'static str {
        match self {
            Self::NoRule => "no rule of the profile reaches this RP",
            Self::RuleDenies => "its rule is now deny",
            Self::RuleAllows => "its rule is now allow, so the grant is redundant",
        }
    }
}

/// One granted rule that does nothing, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InertGrant {
    pub rp_id: String,
    pub reason: InertReason,
}

/// The granted rules of `profile` that the configuration no longer lets act.
///
/// A grant is live exactly when resolving its RP over the profile's rules, with the grant
/// present, gives a configured `request` that the grant upgrades (the resolver's own rule, so the
/// wildcard `request` and exact `request` cases agree with the runtime).
pub fn inert_grants(profile: &AgentProfileConfig, grants: &[GrantedRule]) -> Vec<InertGrant> {
    grants
        .iter()
        .filter_map(|grant| {
            let matched = resolve_rules(
                &profile.rules,
                &profile.credential_selection,
                PolicyAction::Authenticate,
                &grant.rp_id,
                |_| true,
            );
            if matched.granted {
                return None;
            }
            let reason = match (&matched.rule, matched.configured) {
                (RuleIdentity::None, _) => InertReason::NoRule,
                (_, RuleAction::Allow) => InertReason::RuleAllows,
                _ => InertReason::RuleDenies,
            };
            Some(InertGrant {
                rp_id: grant.rp_id.clone(),
                reason,
            })
        })
        .collect()
}

/// The `granted_rules_inert` check of one profile: passes with a `warning:` when grants are inert
/// (they are harmless, so the profile stays healthy), and says nothing is inert otherwise.
pub fn inert_grants_check(
    profile: &AgentProfileConfig,
    view: Option<&ProfileGrants>,
) -> DoctorCheck {
    let name = "granted_rules_inert".to_string();
    let Some(view) = view else {
        return DoctorCheck {
            name,
            passed: true,
            message: "no granted-rules store for this profile".into(),
        };
    };
    let inert = inert_grants(profile, view.rules());
    if inert.is_empty() {
        return DoctorCheck {
            name,
            passed: true,
            message: "every granted rule is backed by a request rule".into(),
        };
    }
    let list = inert
        .iter()
        .map(|grant| format!("{} ({})", grant.rp_id, grant.reason.describe()))
        .collect::<Vec<_>>()
        .join("; ");
    DoctorCheck {
        name,
        passed: true,
        message: format!(
            "warning: {} orphaned granted rule(s) are inert: {list}; remove them with \
             `agent-admin grants revoke`",
            inert.len()
        ),
    }
}

/// The profile names that have a store file in `dir` (`<profile>.toml`, excluding the writer's
/// dot-prefixed temporary files) but are not in `configured`.
pub fn unknown_profile_stores(dir: &Path, configured: &BTreeSet<String>) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let file = entry.file_name().into_string().ok()?;
            let name = file.strip_suffix(".toml")?;
            (!name.is_empty() && !name.starts_with('.') && !configured.contains(name))
                .then(|| name.to_string())
        })
        .collect();
    names.sort();
    names
}

/// The `granted_rules_profiles` check: store files of profiles that no longer exist.
pub fn unknown_profile_stores_check(dir: &Path, configured: &BTreeSet<String>) -> DoctorCheck {
    let unknown = unknown_profile_stores(dir, configured);
    if unknown.is_empty() {
        return DoctorCheck {
            name: "granted_rules_profiles".into(),
            passed: true,
            message: "every granted-rules store belongs to a configured profile".into(),
        };
    }
    DoctorCheck {
        name: "granted_rules_profiles".into(),
        passed: true,
        message: format!(
            "warning: orphaned granted-rules store(s) of profile(s) no longer configured: {} \
             (in {}); they are never read, delete the files if the profiles are gone for good",
            unknown.join(", "),
            dir.display()
        ),
    }
}

/// The offline `doctor --agents` checks: per profile, inert grants, then the pin, wildcard
/// registration and advisory checks of [`super::doctor_pins`] (`human` locates the human
/// credential store for same-user profiles); once, stores of profiles that no longer exist. Reads
/// the stores through the daemon's own loader (fail-closed checks and all) and the credential
/// stores through their path indexes only, writes nothing.
pub fn run(
    config: &AgentConfig,
    euid: u32,
    human: Option<&super::doctor_pins::HumanStore>,
) -> Vec<DoctorCheck> {
    let Some(state_dir) = config.effective_state_dir(euid) else {
        return Vec::new();
    };
    let ids: Vec<(String, ProfileId)> = config
        .profiles
        .keys()
        .filter_map(|name| ProfileId::new(name).ok().map(|id| (name.clone(), id)))
        .collect();
    let store =
        GrantedRulesStore::open_with_owner(&state_dir, ids.iter().map(|(_, id)| id.clone()), euid);
    let mut checks = Vec::new();
    for (name, id) in &ids {
        let Some(profile) = config.profiles.get(name) else {
            continue;
        };
        let mut check = inert_grants_check(profile, store.profile(id).as_deref());
        check.message = format!("profile '{name}': {}", check.message);
        checks.push(check);
    }
    checks.extend(super::doctor_pins::run(config, human, &|name| {
        ProfileId::new(name).ok().and_then(|id| store.profile(&id))
    }));
    let configured: BTreeSet<String> = config.profiles.keys().cloned().collect();
    checks.push(unknown_profile_stores_check(
        &state_dir.join(GRANTED_RULES_DIR),
        &configured,
    ));
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    use passless_core::agent::AgentRpRule;

    use super::super::granted_rules::{GrantKind, PermittingRule};

    fn rule(rp_id: &str, authenticate: RuleAction) -> AgentRpRule {
        AgentRpRule {
            rp_id: rp_id.to_string(),
            register: RuleAction::Deny,
            authenticate,
            credential_selection: None,
        }
    }

    fn profile(rules: Vec<AgentRpRule>) -> AgentProfileConfig {
        let mut text = String::from("mode = \"same-user\"\nprincipal_user = \"alice\"\n");
        for rule in rules {
            text.push_str(&format!(
                "[[rules]]\nrp_id = \"{}\"\nauthenticate = \"{}\"\n",
                rule.rp_id, rule.authenticate
            ));
        }
        toml::from_str(&text).unwrap()
    }

    fn grant(rp_id: &str) -> GrantedRule {
        GrantedRule::new(
            rp_id,
            GrantKind::Escalation,
            "req",
            "https://example.com",
            PermittingRule::Exact,
            None,
        )
    }

    #[test]
    fn a_grant_under_a_request_rule_is_live() {
        let profile = profile(vec![rule("github.com", RuleAction::Request)]);
        assert!(inert_grants(&profile, &[grant("github.com")]).is_empty());
    }

    #[test]
    fn a_grant_under_the_wildcard_request_rule_is_live() {
        let profile = profile(vec![rule("*", RuleAction::Request)]);
        assert!(inert_grants(&profile, &[grant("github.com")]).is_empty());
    }

    #[test]
    fn a_grant_for_an_rp_no_rule_reaches_is_orphaned() {
        let profile = profile(vec![rule("github.com", RuleAction::Request)]);
        let inert = inert_grants(&profile, &[grant("gitlab.com")]);
        assert_eq!(
            inert,
            vec![InertGrant {
                rp_id: "gitlab.com".into(),
                reason: InertReason::NoRule
            }]
        );
        // A profile with no rules at all leaves every grant orphaned.
        assert_eq!(
            inert_grants(&profile_without_rules(), &[grant("github.com")])[0].reason,
            InertReason::NoRule
        );
    }

    fn profile_without_rules() -> AgentProfileConfig {
        profile(Vec::new())
    }

    #[test]
    fn a_grant_is_inert_when_its_rule_became_deny() {
        let profile = profile(vec![rule("github.com", RuleAction::Deny)]);
        assert_eq!(
            inert_grants(&profile, &[grant("github.com")])[0].reason,
            InertReason::RuleDenies
        );
        // An exact deny also beats a wildcard request.
        let profile = self::profile(vec![
            rule("*", RuleAction::Request),
            rule("github.com", RuleAction::Deny),
        ]);
        assert_eq!(
            inert_grants(&profile, &[grant("github.com")])[0].reason,
            InertReason::RuleDenies
        );
    }

    #[test]
    fn a_grant_is_redundant_when_its_rule_became_allow() {
        let profile = profile(vec![rule("github.com", RuleAction::Allow)]);
        assert_eq!(
            inert_grants(&profile, &[grant("github.com")])[0].reason,
            InertReason::RuleAllows
        );
    }

    #[test]
    fn only_the_inert_grants_are_reported() {
        let profile = profile(vec![
            rule("github.com", RuleAction::Request),
            rule("bank.example", RuleAction::Deny),
        ]);
        let inert = inert_grants(
            &profile,
            &[
                grant("github.com"),
                grant("bank.example"),
                grant("gone.example"),
            ],
        );
        let names: Vec<_> = inert.iter().map(|g| g.rp_id.as_str()).collect();
        assert_eq!(names, ["bank.example", "gone.example"]);
    }

    #[test]
    fn the_check_warns_without_failing_and_names_each_orphan() {
        let profile = profile(vec![rule("github.com", RuleAction::Deny)]);
        let view = ProfileGrants::Enabled(vec![grant("github.com")]);
        let check = inert_grants_check(&profile, Some(&view));
        assert!(check.passed, "an inert grant is harmless: {check:?}");
        assert!(check.message.starts_with("warning:"), "{check:?}");
        assert!(check.message.contains("github.com"), "{check:?}");
        assert!(check.message.contains("orphaned"), "{check:?}");
    }

    #[test]
    fn the_check_is_quiet_when_every_grant_is_live_or_there_are_none() {
        let profile = profile(vec![rule("github.com", RuleAction::Request)]);
        for view in [
            ProfileGrants::Enabled(vec![grant("github.com")]),
            ProfileGrants::Enabled(Vec::new()),
            ProfileGrants::Disabled("broken".into()),
        ] {
            let check = inert_grants_check(&profile, Some(&view));
            assert!(check.passed);
            assert!(!check.message.contains("warning"), "{check:?}");
        }
    }

    #[test]
    fn store_files_of_profiles_that_no_longer_exist_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        for file in [
            "kept.toml",
            "gone.toml",
            ".gone.toml.tmp",
            "notes.txt",
            ".hidden.toml",
        ] {
            fs::write(dir.path().join(file), "").unwrap();
        }
        let configured: BTreeSet<String> = ["kept".to_string()].into();
        assert_eq!(unknown_profile_stores(dir.path(), &configured), ["gone"]);

        let check = unknown_profile_stores_check(dir.path(), &configured);
        assert!(check.passed);
        assert!(check.message.contains("gone"), "{check:?}");
        assert!(check.message.contains("orphaned"), "{check:?}");

        let all: BTreeSet<String> = ["kept".to_string(), "gone".to_string()].into();
        assert!(
            !unknown_profile_stores_check(dir.path(), &all)
                .message
                .contains("warning")
        );
        // A missing directory has nothing to report.
        assert!(unknown_profile_stores(&dir.path().join("absent"), &configured).is_empty());
    }

    #[test]
    fn the_offline_run_reads_the_stores_and_flags_orphans_and_vanished_profiles() {
        use std::os::unix::fs::PermissionsExt;

        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join(GRANTED_RULES_DIR);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let store = |profile: &str, rp: &str| {
            let path = dir.join(format!("{profile}.toml"));
            fs::write(
                &path,
                format!(
                    "version = 1\nprofile = \"{profile}\"\n[[grant]]\nrp_id = \"{rp}\"\n\
                     action = \"authenticate\"\nkind = \"escalation\"\n\
                     granted_at = \"2026-01-01T00:00:00Z\"\nrequest_id = \"r\"\n\
                     origin = \"https://{rp}\"\nrule = \"exact\"\n"
                ),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        };
        store("live", "github.com");
        store("denied", "github.com");
        store("vanished", "github.com");
        let config: AgentConfig = toml::from_str(&format!(
            "state_dir = \"{}\"\n\
             [profiles.live]\nmode = \"same-user\"\nprincipal_user = \"alice\"\n\
             [[profiles.live.rules]]\nrp_id = \"github.com\"\nauthenticate = \"request\"\n\
             [profiles.denied]\nmode = \"same-user\"\nprincipal_user = \"alice\"\n\
             [[profiles.denied.rules]]\nrp_id = \"github.com\"\nauthenticate = \"deny\"\n",
            state.path().display()
        ))
        .unwrap();
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };

        let checks = run(&config, euid, None);
        let message_of = |needle: &str| {
            checks
                .iter()
                .find(|check| check.message.contains(needle))
                .unwrap_or_else(|| panic!("no check mentions {needle}: {checks:?}"))
        };
        assert!(
            message_of("profile 'denied'")
                .message
                .contains("orphaned granted rule")
        );
        assert!(
            !message_of("profile 'live'").message.contains("warning"),
            "{checks:?}"
        );
        assert!(message_of("vanished").message.starts_with("warning:"));
    }
}
