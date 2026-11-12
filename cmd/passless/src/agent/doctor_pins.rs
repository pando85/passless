//! Profile pins and wildcard registration in the doctor reports (ADR 0014 amendment sections 2.1
//! and 2.2).
//!
//! Profile `credential_refs` may coexist with the `*` rule: the pins constrain the exact rules,
//! and RPs matched by `*` use discovery. An operator can misread the list as "the agent may only
//! ever use these credentials", so the reports say what it covers, and warn about pins that do
//! nothing (the credential belongs to an RP with no usable exact rule) or whose credential is not
//! in the store. A `*` rule that requests registration is bounded by a cap and a daily prompt
//! limit; the reports show how much of the cap the stored grants use.
//!
//! The checks are pure over the configuration, the loaded grants and a [`StoreView`]. A pin is
//! located in the store through the path index (RP directory and credential file names): no
//! credential is read, decrypted or unsealed. `profile check` runs [`profile_checks`] on the
//! daemon's live view, `doctor --agents` runs [`run`] offline.

use std::collections::BTreeSet;
use std::path::Path;

use passless_core::agent::protocol::DoctorCheck;
use passless_core::agent::{
    AgentConfig, AgentMode, AgentProfileConfig, CredentialRef, PolicyAction, RuleAction,
    RuleIdentity, resolve_rules,
};
use passless_core::config::BackendConfig;

use super::granted_rules::{ProfileGrants, wildcard_registration_count};

use crate::storage::index::load_credential_paths;

/// What the profile's credential store holds, as far as the path index tells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreView {
    /// `(RP ID, credential reference)` for every credential in the store.
    Known(Vec<(String, CredentialRef)>),
    /// The store cannot be inspected without decrypting, or could not be read; the reason.
    Unknown(String),
}

impl StoreView {
    /// A view from `(RP ID, credential ID)` pairs, as the storage index lists them.
    pub fn from_indexed(credentials: Vec<(String, Vec<u8>)>) -> Self {
        Self::Known(
            credentials
                .into_iter()
                .map(|(rp_id, id)| (rp_id, CredentialRef::with_default_domain(&id)))
                .collect(),
        )
    }

    /// The view of a credential directory with files of `extension`, read from file names alone.
    pub fn from_directory(dir: &Path, extension: &str) -> Self {
        match load_credential_paths(dir, extension) {
            Ok(indexes) => Self::from_indexed(indexes.credentials()),
            Err(e) => Self::Unknown(format!("cannot list {}: {e}", dir.display())),
        }
    }

    /// The RP a credential belongs to, when the store holds it.
    fn rp_of(&self, credential: &CredentialRef) -> Option<&str> {
        match self {
            Self::Known(all) => all
                .iter()
                .find(|(_, held)| held == credential)
                .map(|(rp_id, _)| rp_id.as_str()),
            Self::Unknown(_) => None,
        }
    }
}

/// Why a pin does nothing, or is not usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinFinding {
    /// The credential is not in the store: operations at the exact rules fail closed.
    Missing { credential: String },
    /// The credential belongs to an RP that no exact rule reaches (`*` or no rule): the pin is
    /// inert, since a wildcard match never uses the pins.
    NoExactRule { credential: String, rp_id: String },
    /// The credential's exact rule denies `authenticate`.
    RuleDenies { credential: String, rp_id: String },
}

impl PinFinding {
    fn describe(&self) -> String {
        match self {
            Self::Missing { credential } => format!(
                "pin {credential} is not in the store (operations at an exact rule fail closed \
                 until the credential is restored or the pin is removed)"
            ),
            Self::NoExactRule { credential, rp_id } => format!(
                "pin {credential} belongs to {rp_id}, which has no exact rule: inert (the `*` \
                 rule uses discovery, never the pins)"
            ),
            Self::RuleDenies { credential, rp_id } => format!(
                "pin {credential} belongs to {rp_id}, whose exact rule denies authenticate: inert"
            ),
        }
    }
}

/// The form the rules and the store index share: trimmed and lowercase.
fn normalize_rp_id(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn short(credential: &CredentialRef) -> String {
    credential.to_hex().chars().take(12).collect()
}

fn exact_rule_count(profile: &AgentProfileConfig) -> usize {
    profile
        .rules
        .iter()
        .filter(|rule| !rule.is_wildcard())
        .count()
}

fn has_wildcard(profile: &AgentProfileConfig) -> bool {
    profile.rules.iter().any(|rule| rule.is_wildcard())
}

/// The pin coverage note for a profile that has both `credential_refs` and a `*` rule (the one
/// combination where the list is easy to misread as global): what the pins constrain and what
/// they do not. `None` when the profile has no pins or no `*` rule.
pub fn pin_coverage(profile: &AgentProfileConfig) -> Option<String> {
    let pins = profile.credential_refs.as_ref()?;
    if !has_wildcard(profile) {
        return None;
    }
    Some(format!(
        "credential_refs ({}) constrain the {} exact rule(s); RPs matched by `*` use discovery",
        pins.len(),
        exact_rule_count(profile)
    ))
}

/// Pins that do nothing or point at nothing, found by locating each pin in `view`.
///
/// An unknown view finds nothing (the caller reports that it could not look). Besides the
/// per-pin findings, an exact rule that can authenticate but whose RP has no pinned credential in
/// the store is reported by [`unpinned_exact_rules`].
pub fn pin_findings(profile: &AgentProfileConfig, view: &StoreView) -> Vec<PinFinding> {
    let Some(pins) = &profile.credential_refs else {
        return Vec::new();
    };
    if matches!(view, StoreView::Unknown(_)) {
        return Vec::new();
    }
    pins.iter()
        .filter_map(|pin| {
            let credential = short(pin);
            let Some(rp_id) = view.rp_of(pin) else {
                return Some(PinFinding::Missing { credential });
            };
            let matched = resolve_rules(
                &profile.rules,
                &profile.credential_selection,
                PolicyAction::Authenticate,
                rp_id,
                |_| false,
            );
            match (&matched.rule, matched.configured) {
                (RuleIdentity::Exact(_), RuleAction::Deny) => Some(PinFinding::RuleDenies {
                    credential,
                    rp_id: rp_id.to_string(),
                }),
                (RuleIdentity::Exact(_), _) => None,
                _ => Some(PinFinding::NoExactRule {
                    credential,
                    rp_id: rp_id.to_string(),
                }),
            }
        })
        .collect()
}

/// Exact rules with `authenticate` other than `deny` and no `register` that could create one,
/// while profile pins are set and none of the pins belongs to the rule's RP in the store: the
/// pins leave the RP with no candidate, so every sign-in there fails closed
/// (`credential_not_match`).
pub fn unpinned_exact_rules(profile: &AgentProfileConfig, view: &StoreView) -> Vec<String> {
    let Some(pins) = &profile.credential_refs else {
        return Vec::new();
    };
    if matches!(view, StoreView::Unknown(_)) {
        return Vec::new();
    }
    let pinned_rps: BTreeSet<String> = pins
        .iter()
        .filter_map(|pin| view.rp_of(pin))
        .map(normalize_rp_id)
        .collect();
    profile
        .rules
        .iter()
        .filter(|rule| !rule.is_wildcard())
        .filter(|rule| rule.authenticate != RuleAction::Deny && rule.register == RuleAction::Deny)
        .map(|rule| normalize_rp_id(&rule.rp_id))
        .filter(|rp_id| !pinned_rps.contains(rp_id))
        .collect()
}

/// The `pin_coverage` check: what the profile's pins constrain. Present only when the profile has
/// both pins and a `*` rule.
pub fn pin_coverage_check(profile: &AgentProfileConfig) -> Option<DoctorCheck> {
    pin_coverage(profile).map(|message| DoctorCheck {
        name: "pin_coverage".into(),
        passed: true,
        message,
    })
}

/// The `pin_health` check: inert and missing pins. Passes with a `warning:` when something is
/// wrong (the pins fail closed or do nothing, which is harmless to the policy), and is absent for
/// a profile without pins.
pub fn pin_health_check(profile: &AgentProfileConfig, view: &StoreView) -> Option<DoctorCheck> {
    let pins = profile.credential_refs.as_ref()?;
    let name = "pin_health".to_string();
    if let StoreView::Unknown(why) = view {
        return Some(DoctorCheck {
            name,
            passed: true,
            message: format!("warning: the pins were not checked against the store: {why}"),
        });
    }
    let mut problems: Vec<String> = pin_findings(profile, view)
        .iter()
        .map(PinFinding::describe)
        .collect();
    for rp_id in unpinned_exact_rules(profile, view) {
        problems.push(format!(
            "the exact rule for {rp_id} has no pinned credential in the store: sign-in there \
             fails closed"
        ));
    }
    if problems.is_empty() {
        return Some(DoctorCheck {
            name,
            passed: true,
            message: format!(
                "all {} pin(s) are in the store and reached by an exact rule",
                pins.len()
            ),
        });
    }
    Some(DoctorCheck {
        name,
        passed: true,
        message: format!("warning: {}", problems.join("; ")),
    })
}

/// The `wildcard_registrations` check of a profile whose `*` rule requests registration (or that
/// still holds wildcard registration grants): the stored grants against
/// `max_wildcard_registrations`, and the daily prompt limit. Passes with a `warning:` at or over
/// the cap, where new registrations at unlisted sites are refused without a prompt.
pub fn wildcard_registration_check(
    profile: &AgentProfileConfig,
    grants: Option<&ProfileGrants>,
) -> Option<DoctorCheck> {
    let stored = grants.map(|view| wildcard_registration_count(view.rules()));
    if !profile.has_wildcard_registration() && stored.unwrap_or(0) == 0 {
        return None;
    }
    let name = "wildcard_registrations".to_string();
    let cap = usize::from(profile.effective_max_wildcard_registrations());
    let per_day = profile.effective_wildcard_registration_prompts_per_day();
    let Some(stored) = stored else {
        return Some(DoctorCheck {
            name,
            passed: true,
            message: format!(
                "wildcard registration: cap {cap} (max_wildcard_registrations), at most \
                 {per_day} prompt(s) per rolling 24 hours (wildcard_registration_prompts_per_day); \
                 no granted-rules store to count"
            ),
        });
    };
    let limits = format!(
        "{stored} of {cap} wildcard registration(s) used (max_wildcard_registrations); at most \
         {per_day} prompt(s) per rolling 24 hours (wildcard_registration_prompts_per_day)"
    );
    let message = if !profile.has_wildcard_registration() {
        format!(
            "warning: {limits}; the `*` rule no longer requests registration, so these grants \
             only matter while it requests authenticate"
        )
    } else if stored >= cap {
        format!(
            "warning: {limits}; at the cap, so registration at unlisted sites is refused without \
             a prompt until a grant is revoked (`agent-admin grants revoke`)"
        )
    } else {
        limits
    };
    Some(DoctorCheck {
        name,
        passed: true,
        message,
    })
}

/// The advisory warnings of `config` that name `profile_name` (wildcard registration keys without
/// effect, a stale `acknowledge_global_registration` entry), one `config_warning` check each.
pub fn advisory_checks(config: &AgentConfig, profile_name: &str) -> Vec<DoctorCheck> {
    let quoted = format!("'{profile_name}'");
    config
        .advisory_warnings()
        .into_iter()
        .filter(|warning| warning.contains(&quoted))
        .map(|warning| DoctorCheck {
            name: "config_warning".into(),
            passed: true,
            message: format!("warning: {warning}"),
        })
        .collect()
}

/// Every pin, wildcard registration and advisory check of one profile, in report order.
pub fn profile_checks(
    config: &AgentConfig,
    profile_name: &str,
    profile: &AgentProfileConfig,
    grants: Option<&ProfileGrants>,
    view: &StoreView,
) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    checks.extend(pin_coverage_check(profile));
    checks.extend(pin_health_check(profile, view));
    checks.extend(wildcard_registration_check(profile, grants));
    checks.extend(advisory_checks(config, profile_name));
    checks
}

/// Where the human credential store lives, for the offline report: directory and file extension
/// of the configured backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanStore {
    pub dir: std::path::PathBuf,
    pub extension: &'static str,
}

impl HumanStore {
    /// The credential directory of the configured backend (`local`, `pass` or `tpm`).
    pub fn from_backend(backend: &BackendConfig) -> Self {
        let extension = match backend {
            BackendConfig::Local { .. } => "bin",
            BackendConfig::Pass { .. } => "gpg",
            #[cfg(feature = "tpm")]
            BackendConfig::Tpm { .. } => "tpm",
        };
        Self {
            dir: backend.state_path(),
            extension,
        }
    }
}

fn isolated_extension(storage: &passless_core::agent::AgentStorageConfig) -> &'static str {
    use passless_core::agent::AgentStorageConfig;

    match storage {
        AgentStorageConfig::Local { .. } => "bin",
        AgentStorageConfig::Pass { .. } => "gpg",
        #[cfg(feature = "tpm")]
        AgentStorageConfig::Tpm { .. } => "tpm",
    }
}

/// The offline `doctor --agents` checks: per profile, the pin, wildcard registration and advisory
/// checks, each named `<profile>: <check>`. The stores are read through their path indexes
/// only. `grants` gives the stored granted rules of a profile.
pub fn run(
    config: &AgentConfig,
    human: Option<&HumanStore>,
    grants: &dyn Fn(&str) -> Option<std::sync::Arc<ProfileGrants>>,
) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    for (name, profile) in &config.profiles {
        let view = match (profile.mode, &profile.storage, human) {
            (AgentMode::Isolated, Some(storage), _) => StoreView::from_directory(
                &storage.credential_state_path(),
                isolated_extension(storage),
            ),
            (AgentMode::Isolated, None, _) => {
                StoreView::Unknown("the isolated profile has no storage configuration".into())
            }
            (AgentMode::SameUser, _, Some(store)) => {
                StoreView::from_directory(&store.dir, store.extension)
            }
            (AgentMode::SameUser, _, None) => {
                StoreView::Unknown("the human credential backend is not known here".into())
            }
        };
        let stored = grants(name);
        for mut check in profile_checks(config, name, profile, stored.as_deref(), &view) {
            // The profile goes into the name, as the browser checks do, so that a message that
            // starts with `warning:` still prints as a warning.
            check.name = format!("{name}: {}", check.name);
            checks.push(check);
        }
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::granted_rules::{GrantKind, GrantedRule, PermittingRule};

    fn cred_id(n: u8) -> Vec<u8> {
        vec![n; 16]
    }

    fn pin(n: u8) -> CredentialRef {
        CredentialRef::with_default_domain(&cred_id(n))
    }

    fn view(entries: &[(&str, u8)]) -> StoreView {
        StoreView::from_indexed(
            entries
                .iter()
                .map(|(rp, n)| (rp.to_string(), cred_id(*n)))
                .collect(),
        )
    }

    /// A same-user profile with `rules` (`rp`, `authenticate`, `register`) and optional pins.
    fn profile(rules: &[(&str, &str, &str)], pins: Option<&[u8]>) -> AgentProfileConfig {
        let mut text = String::from("mode = \"same-user\"\nprincipal_user = \"alice\"\n");
        if let Some(pins) = pins {
            let list: Vec<String> = pins
                .iter()
                .map(|n| format!("\"{}\"", pin(*n).to_hex()))
                .collect();
            text.push_str(&format!("credential_refs = [{}]\n", list.join(", ")));
        }
        for (rp, authenticate, register) in rules {
            text.push_str(&format!(
                "[[rules]]\nrp_id = \"{rp}\"\nauthenticate = \"{authenticate}\"\n\
                 register = \"{register}\"\n"
            ));
        }
        toml::from_str(&text).unwrap()
    }

    fn grant(rp_id: &str, kind: GrantKind, rule: PermittingRule) -> GrantedRule {
        GrantedRule::new(
            rp_id,
            kind,
            "req",
            "https://example.com",
            rule,
            matches!(kind, GrantKind::Registration).then(|| pin(9)),
        )
    }

    fn config_with(profile_text: &str, extra: &str) -> AgentConfig {
        toml::from_str(&format!(
            "{extra}\n[profiles.coding]\nmode = \"same-user\"\nprincipal_user = \"alice\"\n\
             {profile_text}"
        ))
        .unwrap()
    }

    #[test]
    fn coverage_counts_pins_and_exact_rules_and_names_the_wildcard() {
        let profile = profile(
            &[
                ("github.com", "allow", "deny"),
                ("gitlab.com", "allow", "deny"),
                ("*", "request", "deny"),
            ],
            Some(&[1, 2, 3]),
        );
        assert_eq!(
            pin_coverage(&profile).unwrap(),
            "credential_refs (3) constrain the 2 exact rule(s); RPs matched by `*` use discovery"
        );
        let check = pin_coverage_check(&profile).unwrap();
        assert!(check.passed);
        assert_eq!(check.mark(), "ok");
    }

    #[test]
    fn coverage_is_silent_without_pins_or_without_the_wildcard() {
        let no_pins = profile(
            &[("github.com", "allow", "deny"), ("*", "request", "deny")],
            None,
        );
        assert!(pin_coverage(&no_pins).is_none());
        let no_wildcard = profile(&[("github.com", "allow", "deny")], Some(&[1]));
        assert!(pin_coverage(&no_wildcard).is_none());
        // An empty pin list is still a pin list: it constrains the exact rules to nothing.
        let empty = profile(
            &[("github.com", "allow", "deny"), ("*", "request", "deny")],
            Some(&[]),
        );
        assert!(
            pin_coverage(&empty)
                .unwrap()
                .starts_with("credential_refs (0)")
        );
    }

    #[test]
    fn a_pin_reached_by_an_exact_rule_is_healthy() {
        let profile = profile(
            &[("github.com", "allow", "deny"), ("*", "request", "deny")],
            Some(&[1]),
        );
        let store = view(&[("github.com", 1), ("other.example", 7)]);
        assert!(pin_findings(&profile, &store).is_empty());
        assert!(unpinned_exact_rules(&profile, &store).is_empty());
        let check = pin_health_check(&profile, &store).unwrap();
        assert_eq!(check.mark(), "ok", "{check:?}");
        assert!(check.message.contains("1 pin(s)"), "{check:?}");
    }

    #[test]
    fn a_pin_for_an_rp_without_an_exact_rule_is_inert() {
        let profile = profile(
            &[("github.com", "allow", "deny"), ("*", "request", "deny")],
            Some(&[1, 2]),
        );
        // Credential 2 sits at an RP that only `*` reaches.
        let store = view(&[("github.com", 1), ("unlisted.example", 2)]);
        let findings = pin_findings(&profile, &store);
        assert_eq!(
            findings,
            vec![PinFinding::NoExactRule {
                credential: short(&pin(2)),
                rp_id: "unlisted.example".into()
            }]
        );
        let check = pin_health_check(&profile, &store).unwrap();
        assert!(check.passed, "an inert pin is harmless: {check:?}");
        assert_eq!(check.mark(), "warn");
        assert!(check.message.contains("unlisted.example"), "{check:?}");
        assert!(check.message.contains("inert"), "{check:?}");
    }

    #[test]
    fn a_pin_for_an_rp_no_rule_reaches_is_inert_too() {
        let profile = profile(&[("github.com", "allow", "deny")], Some(&[2]));
        let store = view(&[("gone.example", 2)]);
        assert!(matches!(
            pin_findings(&profile, &store)[..],
            [PinFinding::NoExactRule { .. }]
        ));
    }

    #[test]
    fn a_pin_whose_exact_rule_denies_is_inert() {
        let profile = profile(
            &[("github.com", "deny", "deny"), ("*", "request", "deny")],
            Some(&[1]),
        );
        let store = view(&[("github.com", 1)]);
        assert!(matches!(
            pin_findings(&profile, &store)[..],
            [PinFinding::RuleDenies { .. }]
        ));
    }

    #[test]
    fn a_pin_missing_from_the_store_is_reported_and_fails_closed() {
        let profile = profile(
            &[("github.com", "allow", "deny"), ("*", "request", "deny")],
            Some(&[1, 5]),
        );
        let store = view(&[("github.com", 1)]);
        assert_eq!(
            pin_findings(&profile, &store),
            vec![PinFinding::Missing {
                credential: short(&pin(5))
            }]
        );
        let check = pin_health_check(&profile, &store).unwrap();
        assert_eq!(check.mark(), "warn");
        assert!(check.message.contains(&short(&pin(5))), "{check:?}");
        assert!(check.message.contains("fail closed"), "{check:?}");
        // The pin text never carries more than a short prefix of the reference.
        assert!(!check.message.contains(&pin(5).to_hex()), "{check:?}");
    }

    #[test]
    fn an_exact_rule_with_no_pinned_credential_fails_closed_unless_it_can_register() {
        let profile = profile(
            &[
                ("github.com", "allow", "deny"),
                ("gitlab.com", "allow", "deny"),
                ("new.example", "allow", "request"),
                ("blocked.example", "deny", "deny"),
                ("*", "request", "deny"),
            ],
            Some(&[1]),
        );
        let store = view(&[("github.com", 1)]);
        assert_eq!(unpinned_exact_rules(&profile, &store), ["gitlab.com"]);
        let check = pin_health_check(&profile, &store).unwrap();
        assert!(check.message.contains("gitlab.com"), "{check:?}");
        assert!(!check.message.contains("new.example"), "{check:?}");
        assert!(!check.message.contains("blocked.example"), "{check:?}");
    }

    #[test]
    fn a_profile_without_pins_has_no_pin_checks() {
        let profile = profile(
            &[("github.com", "allow", "deny"), ("*", "request", "deny")],
            None,
        );
        let store = view(&[("github.com", 1)]);
        assert!(pin_health_check(&profile, &store).is_none());
        assert!(pin_findings(&profile, &store).is_empty());
        assert!(unpinned_exact_rules(&profile, &store).is_empty());
    }

    #[test]
    fn an_unreadable_store_is_a_warning_not_a_guess() {
        let profile = profile(
            &[("github.com", "allow", "deny"), ("*", "request", "deny")],
            Some(&[1]),
        );
        let check =
            pin_health_check(&profile, &StoreView::Unknown("backend is sealed".into())).unwrap();
        assert!(check.passed);
        assert_eq!(check.mark(), "warn");
        assert!(check.message.contains("backend is sealed"), "{check:?}");
    }

    #[test]
    fn pins_are_located_from_file_names_without_reading_any_credential() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        for (rp, n) in [("github.com", 1u8), ("unlisted.example", 2u8)] {
            let rp_dir = dir.path().join(rp);
            std::fs::create_dir_all(&rp_dir).unwrap();
            let file = rp_dir.join(format!("{}.gpg", hex::encode(cred_id(n))));
            std::fs::write(&file, b"not ciphertext").unwrap();
            // Unreadable: a check that opened the file would fail.
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let store = StoreView::from_directory(dir.path(), "gpg");
        let profile = profile(
            &[("github.com", "allow", "deny"), ("*", "request", "deny")],
            Some(&[1, 2]),
        );
        let findings = pin_findings(&profile, &store);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            matches!(&findings[0], PinFinding::NoExactRule { rp_id, .. } if rp_id == "unlisted.example")
        );
        // A directory that does not exist is an empty store: every pin is missing.
        let empty = StoreView::from_directory(&dir.path().join("absent"), "gpg");
        assert_eq!(pin_findings(&profile, &empty).len(), 2);
    }

    #[test]
    fn the_wildcard_count_uses_the_cap_and_the_daily_limit() {
        let mut profile = profile(&[("*", "request", "request")], None);
        profile.max_wildcard_registrations = Some(5);
        profile.wildcard_registration_prompts_per_day = Some(2);
        let stored = ProfileGrants::Enabled(vec![
            grant(
                "a.example",
                GrantKind::Registration,
                PermittingRule::Wildcard,
            ),
            grant(
                "b.example",
                GrantKind::Registration,
                PermittingRule::Wildcard,
            ),
            // Neither of these counts against the cap.
            grant("c.example", GrantKind::Escalation, PermittingRule::Wildcard),
            grant("github.com", GrantKind::Registration, PermittingRule::Exact),
        ]);
        let check = wildcard_registration_check(&profile, Some(&stored)).unwrap();
        assert_eq!(check.name, "wildcard_registrations");
        assert_eq!(check.mark(), "ok", "{check:?}");
        assert!(check.message.contains("2 of 5"), "{check:?}");
        assert!(
            check.message.contains("2 prompt(s) per rolling 24 hours"),
            "{check:?}"
        );
    }

    #[test]
    fn the_wildcard_count_defaults_to_the_documented_limits() {
        let profile = profile(&[("*", "request", "request")], None);
        let stored = ProfileGrants::Enabled(Vec::new());
        let check = wildcard_registration_check(&profile, Some(&stored)).unwrap();
        assert!(check.message.contains("0 of 4"), "{check:?}");
        assert!(check.message.contains("3 prompt(s)"), "{check:?}");
    }

    #[test]
    fn at_the_cap_the_check_warns_that_registration_is_refused_without_a_prompt() {
        let mut profile = profile(&[("*", "request", "request")], None);
        profile.max_wildcard_registrations = Some(1);
        let stored = ProfileGrants::Enabled(vec![grant(
            "a.example",
            GrantKind::Registration,
            PermittingRule::Wildcard,
        )]);
        let check = wildcard_registration_check(&profile, Some(&stored)).unwrap();
        assert!(check.passed, "the cap is working as designed: {check:?}");
        assert_eq!(check.mark(), "warn");
        assert!(check.message.contains("1 of 1"), "{check:?}");
        assert!(check.message.contains("without a prompt"), "{check:?}");
        assert!(check.message.contains("grants revoke"), "{check:?}");
        // A cap below the stored count is valid and refuses just the same.
        profile.max_wildcard_registrations = Some(1);
        let two = ProfileGrants::Enabled(vec![
            grant(
                "a.example",
                GrantKind::Registration,
                PermittingRule::Wildcard,
            ),
            grant(
                "b.example",
                GrantKind::Registration,
                PermittingRule::Wildcard,
            ),
        ]);
        assert!(
            wildcard_registration_check(&profile, Some(&two))
                .unwrap()
                .message
                .contains("2 of 1")
        );
    }

    #[test]
    fn the_wildcard_check_is_absent_when_nothing_involves_wildcard_registration() {
        let profile = profile(&[("*", "request", "deny")], None);
        let stored = ProfileGrants::Enabled(vec![grant(
            "github.com",
            GrantKind::Registration,
            PermittingRule::Exact,
        )]);
        assert!(wildcard_registration_check(&profile, Some(&stored)).is_none());
        assert!(wildcard_registration_check(&profile, None).is_none());
    }

    #[test]
    fn grants_that_outlive_the_wildcard_registration_rule_are_noted() {
        let profile = profile(&[("*", "request", "deny")], None);
        let stored = ProfileGrants::Enabled(vec![grant(
            "a.example",
            GrantKind::Registration,
            PermittingRule::Wildcard,
        )]);
        let check = wildcard_registration_check(&profile, Some(&stored)).unwrap();
        assert_eq!(check.mark(), "warn");
        assert!(
            check.message.contains("no longer requests registration"),
            "{check:?}"
        );
    }

    #[test]
    fn without_a_store_only_the_limits_are_shown() {
        let profile = profile(&[("*", "request", "request")], None);
        let check = wildcard_registration_check(&profile, None).unwrap();
        assert_eq!(check.mark(), "ok");
        assert!(check.message.contains("cap 4"), "{check:?}");
    }

    #[test]
    fn advisories_are_filtered_to_the_profile_they_name() {
        // `coding` sets the keys with no wildcard registration rule; `other` has a stale
        // acknowledgement; `quiet` has neither.
        let text = "
[profiles.coding]
mode = \"same-user\"
principal_user = \"alice\"
max_wildcard_registrations = 2
[[profiles.coding.rules]]
rp_id = \"github.com\"
authenticate = \"allow\"

[profiles.other]
mode = \"same-user\"
principal_user = \"alice\"
[[profiles.other.rules]]
rp_id = \"github.com\"
authenticate = \"allow\"

[profiles.quiet]
mode = \"same-user\"
principal_user = \"alice\"
";
        let config: AgentConfig = toml::from_str(&format!(
            "acknowledge_global_registration = [\"other\"]\n{text}"
        ))
        .unwrap();
        let coding = advisory_checks(&config, "coding");
        assert_eq!(coding.len(), 1, "{coding:?}");
        assert_eq!(coding[0].name, "config_warning");
        assert_eq!(coding[0].mark(), "warn");
        assert!(coding[0].message.contains("max_wildcard_registrations"));
        let other = advisory_checks(&config, "other");
        assert_eq!(other.len(), 1, "{other:?}");
        assert!(other[0].message.contains("stale"), "{other:?}");
        assert!(advisory_checks(&config, "quiet").is_empty());
        // A profile whose name is a prefix of another's is not confused with it.
        assert!(advisory_checks(&config, "cod").is_empty());
    }

    #[test]
    fn profile_checks_run_in_report_order_for_a_fully_configured_profile() {
        let config = config_with("", "");
        let profile = profile(
            &[("github.com", "allow", "deny"), ("*", "request", "request")],
            Some(&[1]),
        );
        let store = view(&[("github.com", 1)]);
        let stored = ProfileGrants::Enabled(Vec::new());
        let checks = profile_checks(&config, "coding", &profile, Some(&stored), &store);
        let names: Vec<_> = checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            ["pin_coverage", "pin_health", "wildcard_registrations"]
        );
    }

    #[test]
    fn the_offline_run_names_each_check_after_its_profile_and_reads_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let rp_dir = dir.path().join("github.com");
        std::fs::create_dir_all(&rp_dir).unwrap();
        std::fs::write(
            rp_dir.join(format!("{}.bin", hex::encode(cred_id(1)))),
            b"x",
        )
        .unwrap();
        let config: AgentConfig = toml::from_str(&format!(
            "[profiles.coding]\nmode = \"same-user\"\nprincipal_user = \"alice\"\n\
             credential_refs = [\"{}\", \"{}\"]\n\
             [[profiles.coding.rules]]\nrp_id = \"github.com\"\nauthenticate = \"allow\"\n\
             [[profiles.coding.rules]]\nrp_id = \"*\"\nauthenticate = \"request\"\n",
            pin(1).to_hex(),
            pin(4).to_hex()
        ))
        .unwrap();
        let human = HumanStore {
            dir: dir.path().to_path_buf(),
            extension: "bin",
        };
        let checks = run(&config, Some(&human), &|_| None);
        assert!(
            checks.iter().all(|c| c.name.starts_with("coding: ")),
            "{checks:?}"
        );
        let health = checks
            .iter()
            .find(|c| c.name == "coding: pin_health")
            .unwrap();
        assert!(health.message.contains("not in the store"), "{health:?}");
        // A warning still prints as one.
        assert_eq!(health.mark(), "warn");
        assert!(checks.iter().any(|c| c.name == "coding: pin_coverage"));

        // Without a known store the pins are reported as not checked.
        let unknown = run(&config, None, &|_| None);
        let health = unknown
            .iter()
            .find(|c| c.name == "coding: pin_health")
            .unwrap();
        assert!(health.message.contains("not checked"), "{health:?}");
    }
}
