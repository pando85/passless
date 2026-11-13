//! Rule resolution (ADR 0014 sections 6.2, 6.3 and 10.1, and its amendment section 4).
//!
//! The effective `authenticate` action for `(profile, rp_id)` is, in this order:
//!
//! 1. an exact rule with `deny` gives `deny`;
//! 2. an exact rule with `allow` gives `allow`;
//! 3. an exact or wildcard rule with `request` gives `allow` when the granted-rules store holds an
//!    entry for the RP that was approved through that same rule (`exact` or `*`), otherwise
//!    `request`;
//! 4. a wildcard rule with `allow` gives `allow`;
//! 5. otherwise `deny`.
//!
//! The effective `register` action is, in this order:
//!
//! 1. an exact rule with `deny` gives `deny`;
//! 2. an exact rule with `allow` gives `allow`;
//! 3. an exact rule with `request` gives `request`;
//! 4. a wildcard rule with `request` gives `request` (rule `*`); a wildcard `allow` (invalid
//!    configuration) gives `deny`, as defence in depth;
//! 5. otherwise `deny`.
//!
//! A rule is a single object per RP, so "exact decides, otherwise the wildcard decides" is the same
//! ordering: an RP with an exact rule never falls through to the wildcard. The granted-rules store
//! can only upgrade an `authenticate` `request` that still exists in the configuration, and only
//! through the rule the grant was approved through: a grant whose rule was removed or set to
//! `deny`, or that was made through `*` at an RP an exact rule now governs (or the reverse), is
//! inert (never consulted). Registration is never
//! upgraded by a grant (one approval, one registration). The wildcard never governs `localhost`,
//! and always selects with `single`.

use super::config::{
    ANY_RP_ID, AgentRpRule, CredentialSelection, LOCALHOST_RP_ID, PolicyAction, RuleAction,
    validate_rp_id,
};

/// The granted-rules store as seen by resolution (ADR 0014 section 8.4). It is consulted only to
/// upgrade a configured `request` for `authenticate`, and only for an exact RP.
///
/// A grant belongs to the rule it was approved through (`exact` or `*`) and upgrades only that
/// rule: every method takes the [`RuleIdentity`] of the rule that matches now, and a grant whose
/// recorded rule differs is not consulted. Otherwise a grant made under the `*` rule would
/// silently widen an exact rule an operator adds later.
///
/// The daemon installs its persistent store; [`NoGrantedRules`] is the empty source.
pub trait GrantSource: Send + Sync {
    /// Whether `profile_id` holds a granted `authenticate = allow` entry for exactly `rp_id` that
    /// was approved through the rule `rule`. `RuleIdentity::None` never matches.
    fn is_granted(
        &self,
        profile_id: &super::ids::ProfileId,
        rp_id: &str,
        rule: &RuleIdentity,
    ) -> bool;

    /// The credential references that registration grants for exactly `rp_id`, approved through
    /// `rule`, pinned (ADR 0014 section 8.3); they join the RP's pinned credential set.
    fn granted_credential_refs(
        &self,
        _profile_id: &super::ids::ProfileId,
        _rp_id: &str,
        _rule: &RuleIdentity,
    ) -> Vec<super::ids::CredentialRef> {
        Vec::new()
    }

    /// Whether the grants for exactly `rp_id` through `rule` include one that is not a
    /// registration grant: an approved `authenticate` escalation ("Allow always"), which permits
    /// sign-in with any credential the rule reaches. When every matching grant is a registration
    /// grant, the upgrade covers only the credentials those grants recorded (section 8.3).
    ///
    /// The default treats a grant that carries no credential reference as an escalation grant.
    fn has_escalation_grant(
        &self,
        profile_id: &super::ids::ProfileId,
        rp_id: &str,
        rule: &RuleIdentity,
    ) -> bool {
        self.is_granted(profile_id, rp_id, rule)
            && self
                .granted_credential_refs(profile_id, rp_id, rule)
                .is_empty()
    }
}

/// A granted-rules store that holds nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGrantedRules;

impl GrantSource for NoGrantedRules {
    fn is_granted(
        &self,
        _profile_id: &super::ids::ProfileId,
        _rp_id: &str,
        _rule: &RuleIdentity,
    ) -> bool {
        false
    }
}

/// Which configured rule decided a resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleIdentity {
    /// The exact rule for this RP.
    Exact(String),
    /// The constrained `*` rule.
    Wildcard,
    /// No rule matched: default deny.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    pub rule: RuleIdentity,
    /// The action configured on the matched rule (`deny` when no rule matched).
    pub configured: RuleAction,
    /// The effective action: `configured`, with `request` upgraded to `allow` by a granted rule.
    pub action: RuleAction,
    /// Whether a granted rule upgraded a `request` to `allow`.
    pub granted: bool,
    /// The credential selection that applies to this match (always `single` for the wildcard).
    pub selection: CredentialSelection,
}

impl MatchedRule {
    /// The rule identity to audit: the exact RP ID, or `*` for a wildcard match.
    pub fn audit_rule(&self) -> Option<&str> {
        match &self.rule {
            RuleIdentity::Exact(rp_id) => Some(rp_id),
            RuleIdentity::Wildcard => Some(ANY_RP_ID),
            RuleIdentity::None => None,
        }
    }

    pub fn is_wildcard(&self) -> bool {
        self.rule == RuleIdentity::Wildcard
    }
}

/// The rule that governs navigation to `host`: the most specific exact rule (an RP ID the host
/// equals or is a subdomain of; the longest RP ID wins, so `login.example.com` beats `example.com`),
/// else the wildcard rule for a valid RP host. `localhost` matches only an exact `localhost` rule.
///
/// This is the host-level counterpart of [`resolve_rules`], used for launch URLs, where there is no
/// separate RP ID: the host may use any of its parent domains as RP ID, and the most specific
/// configured one decides.
pub fn rule_for_host<'a>(rules: &'a [AgentRpRule], host: &str) -> Option<&'a AgentRpRule> {
    let host = host.trim().to_ascii_lowercase();
    if host == LOCALHOST_RP_ID {
        return rules
            .iter()
            .find(|rule| !rule.is_wildcard() && rule.rp_id.trim().eq_ignore_ascii_case(&host));
    }
    if host.ends_with(".localhost") {
        return None;
    }
    let exact = rules
        .iter()
        .filter(|rule| {
            let rp = rule.rp_id.trim().to_ascii_lowercase();
            !rule.is_wildcard()
                && rp != LOCALHOST_RP_ID
                && (host == rp || host.ends_with(&format!(".{rp}")))
        })
        .max_by_key(|rule| rule.rp_id.trim().len());
    exact.or_else(|| {
        validate_rp_id(&host)
            .ok()
            .and_then(|_| rules.iter().find(|rule| rule.is_wildcard()))
    })
}

/// Resolve `(action, rp_id)` over a rule set. `granted` answers whether the granted-rules store
/// holds an exact `authenticate` entry for the RP that was approved through the rule that matched
/// (its identity is the second argument); it is called at most once, only for a configured
/// `authenticate = request`.
pub fn resolve_rules(
    rules: &[AgentRpRule],
    profile_selection: &CredentialSelection,
    action: PolicyAction,
    rp_id: &str,
    granted: impl FnOnce(&str, &RuleIdentity) -> bool,
) -> MatchedRule {
    let denied = |selection: &CredentialSelection| MatchedRule {
        rule: RuleIdentity::None,
        configured: RuleAction::Deny,
        action: RuleAction::Deny,
        granted: false,
        selection: selection.clone(),
    };

    let Ok(normalized) = validate_rp_id(rp_id) else {
        return denied(profile_selection);
    };

    let exact = rules
        .iter()
        .find(|rule| !rule.is_wildcard() && rule.rp_id.trim().eq_ignore_ascii_case(&normalized));
    // The wildcard never governs `localhost` (ADR 0014 6.1/6.3). For registration it is consulted
    // only when it says `request` (amendment section 4): a wildcard `allow` is invalid
    // configuration and a wildcard `deny` is the default deny, so both resolve as no rule.
    let wildcard = if normalized == LOCALHOST_RP_ID {
        None
    } else {
        rules.iter().find(|rule| {
            rule.is_wildcard()
                && (action == PolicyAction::Authenticate || rule.register == RuleAction::Request)
        })
    };

    let (identity, rule) = match (exact, wildcard) {
        (Some(rule), _) => (RuleIdentity::Exact(normalized.clone()), rule),
        (None, Some(rule)) => (RuleIdentity::Wildcard, rule),
        (None, None) => return denied(profile_selection),
    };

    let selection = match identity {
        RuleIdentity::Wildcard => CredentialSelection::Single,
        _ => rule
            .credential_selection
            .clone()
            .unwrap_or_else(|| profile_selection.clone()),
    };
    let configured = rule.action(action);

    // Only an authenticate `request` can be upgraded; register approval is per ceremony (8.3).
    let granted = configured == RuleAction::Request
        && action == PolicyAction::Authenticate
        && granted(&normalized, &identity);
    let effective = if granted {
        RuleAction::Allow
    } else {
        configured
    };

    MatchedRule {
        rule: identity,
        configured,
        action: effective,
        granted,
        selection,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::config::AgentProfileConfig;
    use super::super::ids::ProfileId;

    use std::cell::Cell;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn rule(rp_id: &str, authenticate: RuleAction, register: RuleAction) -> AgentRpRule {
        AgentRpRule {
            rp_id: rp_id.to_string(),
            register,
            authenticate,
            credential_selection: None,
        }
    }

    fn with_selection(mut rule: AgentRpRule, selection: CredentialSelection) -> AgentRpRule {
        rule.credential_selection = Some(selection);
        rule
    }

    /// Resolve with a granted-rules store that holds `granted` and counts its consultations.
    fn resolve_counting(
        rules: &[AgentRpRule],
        action: PolicyAction,
        rp_id: &str,
        granted: &[&str],
    ) -> (MatchedRule, usize) {
        let calls = Cell::new(0usize);
        let matched = resolve_rules(
            rules,
            &CredentialSelection::Single,
            action,
            rp_id,
            |rp, _| {
                calls.set(calls.get() + 1);
                granted.contains(&rp)
            },
        );
        (matched, calls.get())
    }

    fn authenticate(rules: &[AgentRpRule], rp_id: &str) -> MatchedRule {
        resolve_counting(rules, PolicyAction::Authenticate, rp_id, &[]).0
    }

    #[test]
    fn exact_deny_beats_wildcard_allow() {
        let rules = [
            rule("*", RuleAction::Allow, RuleAction::Deny),
            rule("bank.example.com", RuleAction::Deny, RuleAction::Deny),
        ];
        let matched = authenticate(&rules, "bank.example.com");
        assert_eq!(matched.action, RuleAction::Deny);
        assert_eq!(matched.configured, RuleAction::Deny);
        assert_eq!(matched.rule, RuleIdentity::Exact("bank.example.com".into()));
        assert!(!matched.granted);

        // Other RPs still fall to the wildcard.
        assert_eq!(authenticate(&rules, "github.com").action, RuleAction::Allow);
    }

    #[test]
    fn exact_allow_beats_wildcard_deny_and_request() {
        for wildcard in [RuleAction::Deny, RuleAction::Request] {
            let rules = [
                rule("*", wildcard, RuleAction::Deny),
                rule("github.com", RuleAction::Allow, RuleAction::Deny),
            ];
            let matched = authenticate(&rules, "github.com");
            assert_eq!(matched.action, RuleAction::Allow, "wildcard = {wildcard}");
            assert_eq!(matched.rule, RuleIdentity::Exact("github.com".into()));
            assert!(!matched.granted);
        }
    }

    #[test]
    fn exact_request_with_wildcard_allow_is_request() {
        // ADR 6.2: the exact rule decides (step 3) before the wildcard allow (step 4).
        let rules = [
            rule("*", RuleAction::Allow, RuleAction::Deny),
            rule("bank.example.com", RuleAction::Request, RuleAction::Deny),
        ];
        let matched = authenticate(&rules, "bank.example.com");
        assert_eq!(matched.action, RuleAction::Request);
        assert_eq!(matched.configured, RuleAction::Request);
        assert_eq!(matched.rule, RuleIdentity::Exact("bank.example.com".into()));
        assert!(!matched.granted);
    }

    #[test]
    fn wildcard_allow_applies_when_no_exact_rule() {
        let rules = [
            rule("*", RuleAction::Allow, RuleAction::Deny),
            rule("other.example.com", RuleAction::Deny, RuleAction::Deny),
        ];
        let matched = authenticate(&rules, "github.com");
        assert_eq!(matched.action, RuleAction::Allow);
        assert_eq!(matched.rule, RuleIdentity::Wildcard);
        assert!(matched.is_wildcard());
    }

    #[test]
    fn wildcard_request_applies_when_no_exact_rule() {
        let rules = [rule("*", RuleAction::Request, RuleAction::Deny)];
        let matched = authenticate(&rules, "github.com");
        assert_eq!(matched.action, RuleAction::Request);
        assert_eq!(matched.rule, RuleIdentity::Wildcard);
    }

    #[test]
    fn default_deny_without_rules_or_for_unlisted_rp() {
        for rules in [
            vec![],
            vec![rule("github.com", RuleAction::Allow, RuleAction::Allow)],
        ] {
            let (matched, calls) = resolve_counting(
                &rules,
                PolicyAction::Authenticate,
                "gitlab.com",
                &["gitlab.com"],
            );
            assert_eq!(matched.action, RuleAction::Deny);
            assert_eq!(matched.configured, RuleAction::Deny);
            assert_eq!(matched.rule, RuleIdentity::None);
            assert_eq!(matched.audit_rule(), None);
            assert!(!matched.granted);
            assert!(!matched.is_wildcard());
            assert_eq!(calls, 0, "a grant never rescues an unlisted RP");
        }
    }

    #[test]
    fn invalid_rp_id_resolves_to_default_deny() {
        let rules = [
            rule("*", RuleAction::Allow, RuleAction::Deny),
            rule("example.com", RuleAction::Allow, RuleAction::Deny),
        ];
        for rp_id in [
            "",
            "   ",
            "com",
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "*",
            "*.example.com",
            "192.168.0.1",
            "example.com.",
            "foo.localhost",
        ] {
            let (matched, calls) =
                resolve_counting(&rules, PolicyAction::Authenticate, rp_id, &[rp_id]);
            assert_eq!(matched.action, RuleAction::Deny, "{rp_id:?}");
            assert_eq!(matched.rule, RuleIdentity::None, "{rp_id:?}");
            assert_eq!(calls, 0, "{rp_id:?}");
        }
    }

    #[test]
    fn rp_id_and_rule_matching_is_case_and_whitespace_insensitive() {
        let rules = [rule("GitHub.com", RuleAction::Allow, RuleAction::Deny)];
        let matched = authenticate(&rules, "  GITHUB.COM ");
        assert_eq!(matched.action, RuleAction::Allow);
        assert_eq!(matched.rule, RuleIdentity::Exact("github.com".into()));
        assert_eq!(matched.audit_rule(), Some("github.com"));
    }

    #[test]
    fn granted_request_upgrades_to_allow() {
        let rules = [rule("example.com", RuleAction::Request, RuleAction::Deny)];
        let (matched, calls) = resolve_counting(
            &rules,
            PolicyAction::Authenticate,
            "example.com",
            &["example.com"],
        );
        assert_eq!(matched.action, RuleAction::Allow);
        assert_eq!(matched.configured, RuleAction::Request);
        assert!(matched.granted);
        assert_eq!(matched.rule, RuleIdentity::Exact("example.com".into()));
        assert_eq!(calls, 1);
    }

    #[test]
    fn request_without_grant_stays_request() {
        let rules = [rule("example.com", RuleAction::Request, RuleAction::Deny)];
        let (matched, calls) =
            resolve_counting(&rules, PolicyAction::Authenticate, "example.com", &[]);
        assert_eq!(matched.action, RuleAction::Request);
        assert_eq!(matched.configured, RuleAction::Request);
        assert!(!matched.granted);
        assert_eq!(calls, 1);

        // A grant for a different RP does not upgrade this one.
        let (matched, _) = resolve_counting(
            &rules,
            PolicyAction::Authenticate,
            "example.com",
            &["other.example.com"],
        );
        assert_eq!(matched.action, RuleAction::Request);
        assert!(!matched.granted);
    }

    #[test]
    fn grant_is_consulted_with_the_normalized_exact_rp_id() {
        let seen = Mutex::new(Vec::new());
        let rules = [rule("example.com", RuleAction::Request, RuleAction::Deny)];
        resolve_rules(
            &rules,
            &CredentialSelection::Single,
            PolicyAction::Authenticate,
            " EXAMPLE.com ",
            |rp, _| {
                seen.lock().unwrap().push(rp.to_string());
                false
            },
        );
        assert_eq!(*seen.lock().unwrap(), vec!["example.com".to_string()]);
    }

    #[test]
    fn grant_is_consulted_with_the_identity_of_the_matched_rule() {
        let seen = Mutex::new(Vec::new());
        let record = |rp: &str, rule: &RuleIdentity| {
            seen.lock().unwrap().push((rp.to_string(), rule.clone()));
            false
        };
        let wildcard = [rule("*", RuleAction::Request, RuleAction::Deny)];
        let exact = [
            rule("*", RuleAction::Request, RuleAction::Deny),
            rule("example.com", RuleAction::Request, RuleAction::Deny),
        ];
        for rules in [&wildcard[..], &exact[..]] {
            resolve_rules(
                rules,
                &CredentialSelection::Single,
                PolicyAction::Authenticate,
                "example.com",
                record,
            );
        }
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                ("example.com".to_string(), RuleIdentity::Wildcard),
                (
                    "example.com".to_string(),
                    RuleIdentity::Exact("example.com".into())
                ),
            ]
        );
    }

    #[test]
    fn granted_wildcard_request_upgrades_through_the_exact_grant() {
        let rules = [rule("*", RuleAction::Request, RuleAction::Deny)];
        let (matched, calls) = resolve_counting(
            &rules,
            PolicyAction::Authenticate,
            "example.com",
            &["example.com"],
        );
        assert_eq!(matched.action, RuleAction::Allow);
        assert_eq!(matched.configured, RuleAction::Request);
        assert!(matched.granted);
        assert_eq!(matched.rule, RuleIdentity::Wildcard);
        assert_eq!(matched.audit_rule(), Some("*"));
        assert_eq!(matched.selection, CredentialSelection::Single);
        assert_eq!(calls, 1);

        let (matched, _) = resolve_counting(
            &rules,
            PolicyAction::Authenticate,
            "example.com",
            &["other.example.com"],
        );
        assert_eq!(matched.action, RuleAction::Request);
    }

    #[test]
    fn orphaned_grants_never_allow_and_are_never_consulted() {
        let granted_everywhere = ["example.com", "github.com", "other.example.com"];

        // No rule at all for the RP.
        let (matched, calls) = resolve_counting(
            &[],
            PolicyAction::Authenticate,
            "example.com",
            &granted_everywhere,
        );
        assert_eq!(matched.action, RuleAction::Deny);
        assert_eq!(matched.rule, RuleIdentity::None);
        assert!(!matched.granted);
        assert_eq!(calls, 0);

        // The rule was changed to deny (exact) or deny (wildcard).
        for rules in [
            vec![rule("example.com", RuleAction::Deny, RuleAction::Deny)],
            vec![rule("*", RuleAction::Deny, RuleAction::Deny)],
        ] {
            let (matched, calls) = resolve_counting(
                &rules,
                PolicyAction::Authenticate,
                "example.com",
                &granted_everywhere,
            );
            assert_eq!(matched.action, RuleAction::Deny);
            assert_eq!(matched.configured, RuleAction::Deny);
            assert!(!matched.granted);
            assert_eq!(calls, 0, "the store is not consulted for a deny rule");
        }

        // Rules that already allow do not consult the store (and do not report a grant).
        for rules in [
            vec![rule("example.com", RuleAction::Allow, RuleAction::Deny)],
            vec![rule("*", RuleAction::Allow, RuleAction::Deny)],
        ] {
            let (matched, calls) = resolve_counting(
                &rules,
                PolicyAction::Authenticate,
                "example.com",
                &granted_everywhere,
            );
            assert_eq!(matched.action, RuleAction::Allow);
            assert_eq!(matched.configured, RuleAction::Allow);
            assert!(!matched.granted, "an allow rule is not a grant upgrade");
            assert_eq!(calls, 0);
        }

        // An exact deny hides a wildcard request, so a grant cannot resurrect it.
        let rules = [
            rule("*", RuleAction::Request, RuleAction::Deny),
            rule("example.com", RuleAction::Deny, RuleAction::Deny),
        ];
        let (matched, calls) = resolve_counting(
            &rules,
            PolicyAction::Authenticate,
            "example.com",
            &granted_everywhere,
        );
        assert_eq!(matched.action, RuleAction::Deny);
        assert_eq!(calls, 0);
    }

    #[test]
    fn grants_never_upgrade_register() {
        let rules = [rule("example.com", RuleAction::Allow, RuleAction::Request)];
        let (matched, calls) = resolve_counting(
            &rules,
            PolicyAction::Register,
            "example.com",
            &["example.com"],
        );
        assert_eq!(matched.action, RuleAction::Request);
        assert_eq!(matched.configured, RuleAction::Request);
        assert!(!matched.granted);
        assert_eq!(
            calls, 0,
            "register approval is per ceremony, not a stored grant"
        );

        // The same rule's authenticate half does upgrade with a grant.
        let (matched, _) = resolve_counting(
            &rules,
            PolicyAction::Authenticate,
            "example.com",
            &["example.com"],
        );
        assert_eq!(matched.action, RuleAction::Allow);
        assert_eq!(matched.configured, RuleAction::Allow);
    }

    #[test]
    fn register_actions_resolve_independently_of_authenticate() {
        let rules = [
            rule("a.example.com", RuleAction::Deny, RuleAction::Allow),
            rule("b.example.com", RuleAction::Allow, RuleAction::Deny),
        ];
        let register = |rp: &str| {
            resolve_counting(&rules, PolicyAction::Register, rp, &[])
                .0
                .action
        };
        assert_eq!(register("a.example.com"), RuleAction::Allow);
        assert_eq!(register("b.example.com"), RuleAction::Deny);
        assert_eq!(
            authenticate(&rules, "a.example.com").action,
            RuleAction::Deny
        );
        assert_eq!(
            authenticate(&rules, "b.example.com").action,
            RuleAction::Allow
        );
    }

    #[test]
    fn wildcard_allow_never_governs_register() {
        // Validation forbids `register = "allow"` on the wildcard, but `resolve_rules` does not
        // apply validation: a rule that slipped through must still never permit registration
        // (amendment section 4, step 4). A wildcard `deny` is the default deny.
        for register in [RuleAction::Allow, RuleAction::Deny] {
            let rules = [rule("*", RuleAction::Allow, register)];
            let (matched, calls) = resolve_counting(
                &rules,
                PolicyAction::Register,
                "example.com",
                &["example.com"],
            );
            assert_eq!(matched.action, RuleAction::Deny, "register = {register}");
            assert_eq!(matched.configured, RuleAction::Deny);
            assert_eq!(matched.rule, RuleIdentity::None);
            assert!(!matched.granted);
            assert_eq!(calls, 0);
        }

        // An exact rule for the same RP still decides registration.
        let rules = [
            rule("*", RuleAction::Allow, RuleAction::Allow),
            rule("example.com", RuleAction::Allow, RuleAction::Request),
        ];
        let matched = resolve_counting(&rules, PolicyAction::Register, "example.com", &[]).0;
        assert_eq!(matched.action, RuleAction::Request);
        assert_eq!(matched.rule, RuleIdentity::Exact("example.com".into()));
    }

    #[test]
    fn wildcard_request_governs_register_at_unlisted_rps_only() {
        let rules = [
            rule("*", RuleAction::Request, RuleAction::Request),
            rule("denied.example", RuleAction::Allow, RuleAction::Deny),
            rule("allowed.example", RuleAction::Allow, RuleAction::Allow),
            rule("asked.example", RuleAction::Allow, RuleAction::Request),
        ];
        let register = |rp: &str| resolve_counting(&rules, PolicyAction::Register, rp, &[rp]);

        // Steps 1 to 3: the exact rule decides and the wildcard is never reached.
        for (rp, expected) in [
            ("denied.example", RuleAction::Deny),
            ("allowed.example", RuleAction::Allow),
            ("asked.example", RuleAction::Request),
        ] {
            let (matched, calls) = register(rp);
            assert_eq!(matched.action, expected, "{rp}");
            assert_eq!(matched.rule, RuleIdentity::Exact(rp.into()), "{rp}");
            assert_eq!(calls, 0, "registration is never upgraded by a grant");
        }

        // Step 4: an unlisted RP resolves to the wildcard `request`, with `single` selection, and
        // a grant for that RP (an earlier wildcard registration) never upgrades it.
        let (matched, calls) = register("unlisted.example");
        assert_eq!(matched.action, RuleAction::Request);
        assert_eq!(matched.configured, RuleAction::Request);
        assert_eq!(matched.rule, RuleIdentity::Wildcard);
        assert_eq!(matched.audit_rule(), Some("*"));
        assert_eq!(matched.selection, CredentialSelection::Single);
        assert!(!matched.granted);
        assert_eq!(calls, 0);

        // A subdomain of an exact rule's RP is another RP: it goes through the wildcard.
        assert_eq!(
            register("sub.denied.example").0.rule,
            RuleIdentity::Wildcard
        );
    }

    #[test]
    fn wildcard_never_governs_localhost_for_either_action() {
        let rules = [rule("*", RuleAction::Request, RuleAction::Request)];
        for action in [PolicyAction::Authenticate, PolicyAction::Register] {
            for rp_id in ["localhost", "LOCALHOST", " localhost "] {
                let (matched, calls) = resolve_counting(&rules, action, rp_id, &["localhost"]);
                assert_eq!(matched.action, RuleAction::Deny, "{action:?} {rp_id:?}");
                assert_eq!(matched.rule, RuleIdentity::None, "{action:?} {rp_id:?}");
                assert_eq!(calls, 0);
            }
        }
        // An exact `localhost` rule is the only way to register there.
        let rules = [
            rule("*", RuleAction::Request, RuleAction::Request),
            rule("localhost", RuleAction::Allow, RuleAction::Request),
        ];
        let matched = resolve_counting(&rules, PolicyAction::Register, "localhost", &[]).0;
        assert_eq!(matched.rule, RuleIdentity::Exact("localhost".into()));
        assert_eq!(matched.action, RuleAction::Request);
    }

    #[test]
    fn wildcard_never_governs_localhost() {
        let rules = [rule("*", RuleAction::Allow, RuleAction::Deny)];
        for rp_id in ["localhost", "LOCALHOST", " localhost "] {
            let (matched, calls) =
                resolve_counting(&rules, PolicyAction::Authenticate, rp_id, &["localhost"]);
            assert_eq!(matched.action, RuleAction::Deny, "{rp_id:?}");
            assert_eq!(matched.rule, RuleIdentity::None, "{rp_id:?}");
            assert_eq!(calls, 0);
        }

        let rules = [
            rule("*", RuleAction::Allow, RuleAction::Deny),
            rule("localhost", RuleAction::Request, RuleAction::Deny),
        ];
        let (matched, _) = resolve_counting(
            &rules,
            PolicyAction::Authenticate,
            "localhost",
            &["localhost"],
        );
        assert_eq!(matched.rule, RuleIdentity::Exact("localhost".into()));
        assert_eq!(matched.action, RuleAction::Allow);
        assert!(matched.granted);
    }

    #[test]
    fn wildcard_match_reports_wildcard_identity_and_forces_single_selection() {
        let rules = [rule("*", RuleAction::Allow, RuleAction::Deny)];
        let matched = resolve_rules(
            &rules,
            &CredentialSelection::Newest,
            PolicyAction::Authenticate,
            "github.com",
            |_, _| false,
        );
        assert_eq!(matched.rule, RuleIdentity::Wildcard);
        assert_eq!(matched.audit_rule(), Some(ANY_RP_ID));
        assert_eq!(matched.audit_rule(), Some("*"));
        assert!(matched.is_wildcard());
        assert_eq!(matched.selection, CredentialSelection::Single);

        // A rule-level override on the wildcard (rejected by validation) is ignored as well.
        let rules = [with_selection(
            rule("*", RuleAction::Allow, RuleAction::Deny),
            CredentialSelection::FirstMatching,
        )];
        let matched = resolve_rules(
            &rules,
            &CredentialSelection::Newest,
            PolicyAction::Authenticate,
            "github.com",
            |_, _| false,
        );
        assert_eq!(matched.selection, CredentialSelection::Single);
    }

    #[test]
    fn exact_match_reports_the_rp_id_for_audit() {
        let rules = [rule("github.com", RuleAction::Allow, RuleAction::Deny)];
        let matched = authenticate(&rules, "github.com");
        assert_eq!(matched.audit_rule(), Some("github.com"));
        assert!(!matched.is_wildcard());
    }

    #[test]
    fn rule_selection_override_beats_profile_default_for_exact_rule() {
        let rules = [
            with_selection(
                rule("github.com", RuleAction::Allow, RuleAction::Deny),
                CredentialSelection::FirstMatching,
            ),
            rule("gitlab.com", RuleAction::Allow, RuleAction::Deny),
        ];
        let resolve = |rp: &str| {
            resolve_rules(
                &rules,
                &CredentialSelection::Newest,
                PolicyAction::Authenticate,
                rp,
                |_, _| false,
            )
        };
        assert_eq!(
            resolve("github.com").selection,
            CredentialSelection::FirstMatching
        );
        // Without an override the profile default applies.
        assert_eq!(resolve("gitlab.com").selection, CredentialSelection::Newest);
        // No match: default deny, carrying the profile default.
        assert_eq!(
            resolve("unlisted.example.com").selection,
            CredentialSelection::Newest
        );
    }

    #[test]
    fn rule_order_does_not_change_the_outcome() {
        let mut rules = vec![
            rule("*", RuleAction::Allow, RuleAction::Deny),
            rule("a.example.com", RuleAction::Deny, RuleAction::Deny),
            rule("b.example.com", RuleAction::Request, RuleAction::Deny),
        ];
        let expected: Vec<_> = ["a.example.com", "b.example.com", "c.example.com"]
            .iter()
            .map(|rp| authenticate(&rules, rp))
            .collect();
        rules.reverse();
        let reversed: Vec<_> = ["a.example.com", "b.example.com", "c.example.com"]
            .iter()
            .map(|rp| authenticate(&rules, rp))
            .collect();
        assert_eq!(expected, reversed);
    }

    /// A granted-rules store backed by a set of `(profile, rp)` pairs that records its queries.
    #[derive(Default)]
    struct TestGrants {
        granted: HashSet<(String, String)>,
        queries: AtomicUsize,
    }

    impl TestGrants {
        fn with(profile: &str, rps: &[&str]) -> Self {
            Self {
                granted: rps
                    .iter()
                    .map(|rp| (profile.to_string(), rp.to_string()))
                    .collect(),
                queries: AtomicUsize::new(0),
            }
        }
    }

    impl GrantSource for TestGrants {
        fn is_granted(&self, profile_id: &ProfileId, rp_id: &str, _rule: &RuleIdentity) -> bool {
            self.queries.fetch_add(1, Ordering::SeqCst);
            self.granted
                .contains(&(profile_id.as_str().to_string(), rp_id.to_string()))
        }
    }

    fn profile(rules_toml: &str) -> AgentProfileConfig {
        toml::from_str(&format!(
            "mode = \"same-user\"\nprincipal_user = \"alice\"\ncredential_selection = \"newest\"\n{rules_toml}"
        ))
        .unwrap()
    }

    #[test]
    fn profile_resolve_has_no_grants() {
        let profile = profile(
            r#"
[[rules]]
rp_id = "example.com"
authenticate = "request"

[[rules]]
rp_id = "github.com"
authenticate = "allow"
"#,
        );
        let matched = profile.resolve(PolicyAction::Authenticate, "example.com");
        assert_eq!(matched.action, RuleAction::Request);
        assert!(!matched.granted);
        assert_eq!(matched.selection, CredentialSelection::Newest);
        assert_eq!(
            profile
                .resolve(PolicyAction::Authenticate, "github.com")
                .action,
            RuleAction::Allow
        );
        assert_eq!(
            profile.resolve(PolicyAction::Register, "github.com").action,
            RuleAction::Deny
        );
    }

    #[test]
    fn profile_resolve_with_consults_the_grant_source_for_this_profile() {
        let profile = profile(
            r#"
[[rules]]
rp_id = "example.com"
authenticate = "request"

[[rules]]
rp_id = "denied.example.com"
authenticate = "deny"

[[rules]]
rp_id = "allowed.example.com"
authenticate = "allow"
"#,
        );
        let coding = ProfileId::new("coding").unwrap();
        let other = ProfileId::new("other").unwrap();
        let grants = TestGrants::with(
            "coding",
            &[
                "example.com",
                "denied.example.com",
                "allowed.example.com",
                "orphan.example.com",
            ],
        );

        let matched =
            profile.resolve_with(&coding, PolicyAction::Authenticate, "example.com", &grants);
        assert_eq!(matched.action, RuleAction::Allow);
        assert_eq!(matched.configured, RuleAction::Request);
        assert!(matched.granted);
        assert_eq!(grants.queries.load(Ordering::SeqCst), 1);

        // Grants are per profile.
        let matched =
            profile.resolve_with(&other, PolicyAction::Authenticate, "example.com", &grants);
        assert_eq!(matched.action, RuleAction::Request);
        assert!(!matched.granted);

        // Orphaned and redundant grants are inert and never consulted.
        let before = grants.queries.load(Ordering::SeqCst);
        for (rp, expected) in [
            ("denied.example.com", RuleAction::Deny),
            ("allowed.example.com", RuleAction::Allow),
            ("orphan.example.com", RuleAction::Deny),
        ] {
            let matched = profile.resolve_with(&coding, PolicyAction::Authenticate, rp, &grants);
            assert_eq!(matched.action, expected, "{rp}");
            assert!(!matched.granted, "{rp}");
        }
        assert_eq!(grants.queries.load(Ordering::SeqCst), before);

        // Registration is never upgraded.
        let matched = profile.resolve_with(&coding, PolicyAction::Register, "example.com", &grants);
        assert_eq!(matched.action, RuleAction::Deny);
        assert_eq!(grants.queries.load(Ordering::SeqCst), before);
    }

    #[test]
    fn no_granted_rules_never_grants() {
        let profile = profile(
            r#"
[[rules]]
rp_id = "example.com"
authenticate = "request"
"#,
        );
        let id = ProfileId::new("coding").unwrap();
        let matched = profile.resolve_with(
            &id,
            PolicyAction::Authenticate,
            "example.com",
            &NoGrantedRules,
        );
        assert_eq!(matched.action, RuleAction::Request);
        assert!(!NoGrantedRules.is_granted(&id, "example.com", &RuleIdentity::Wildcard));
    }

    #[test]
    fn rule_for_host_most_specific_exact_rule_wins() {
        let rules = [
            rule("example.com", RuleAction::Allow, RuleAction::Deny),
            rule("login.example.com", RuleAction::Deny, RuleAction::Deny),
            rule("*", RuleAction::Request, RuleAction::Deny),
        ];
        let rp = |host: &str| rule_for_host(&rules, host).map(|r| r.rp_id.as_str());
        assert_eq!(rp("example.com"), Some("example.com"));
        assert_eq!(rp("app.example.com"), Some("example.com"));
        assert_eq!(rp("login.example.com"), Some("login.example.com"));
        assert_eq!(rp("sso.login.example.com"), Some("login.example.com"));
        assert_eq!(rp("EXAMPLE.com"), Some("example.com"));
        // A suffix that is not a label boundary never matches.
        assert_eq!(rp("notexample.com"), Some("*"));
        assert_eq!(rp("other.org"), Some("*"));
        // Not a valid RP host: no wildcard match.
        assert_eq!(rp("127.0.0.1"), None);
    }

    #[test]
    fn rule_for_host_localhost_is_exact_only() {
        let wildcard_only = [rule("*", RuleAction::Allow, RuleAction::Deny)];
        assert!(rule_for_host(&wildcard_only, "localhost").is_none());
        assert!(rule_for_host(&wildcard_only, "foo.localhost").is_none());
        let exact = [
            rule("localhost", RuleAction::Allow, RuleAction::Deny),
            rule("*", RuleAction::Deny, RuleAction::Deny),
        ];
        assert_eq!(
            rule_for_host(&exact, "localhost").map(|r| r.rp_id.as_str()),
            Some("localhost")
        );
        assert!(rule_for_host(&exact, "foo.localhost").is_none());
        assert!(rule_for_host(&exact, "localhost.").is_none());
        assert!(rule_for_host(&[], "example.com").is_none());
    }
}
