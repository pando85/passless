//! The two deployment axes of ADR 0014 section 13.
//!
//! - `mode` (configured): `same-user` uses the human backend, `isolated` a profile backend.
//! - Principal relationship (derived): the principal's UID against the daemon's UID, `shared-uid`
//!   or `distinct-uid`.
//!
//! `passless doctor` and every audit record report both. This module is the one place the
//! relationship is derived and named, so the audit string values (`shared-uid`, `distinct-uid`)
//! and the doctor output cannot drift apart.

use std::fmt;

use passless_core::agent::AgentMode;
use passless_core::agent::protocol::DoctorCheck;

/// The principal's UID against the daemon's UID (ADR 0014 section 13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalRelationship {
    /// Same UID: no kernel boundary between the agent and the daemon.
    SharedUid,
    /// Different UIDs: a Unix boundary protects the backend, config and granted-rules store.
    DistinctUid,
}

impl PrincipalRelationship {
    pub fn from_uids(principal_uid: u32, daemon_uid: u32) -> Self {
        if principal_uid == daemon_uid {
            Self::SharedUid
        } else {
            Self::DistinctUid
        }
    }

    /// The name audit records and doctor report. Audit consumers match on these strings.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedUid => "shared-uid",
            Self::DistinctUid => "distinct-uid",
        }
    }

    pub fn is_shared_uid(self) -> bool {
        self == Self::SharedUid
    }
}

impl fmt::Display for PrincipalRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One profile's place in the section 13 matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeploymentAxes {
    pub mode: AgentMode,
    pub relationship: PrincipalRelationship,
}

impl DeploymentAxes {
    pub fn new(mode: AgentMode, principal_uid: u32, daemon_uid: u32) -> Self {
        Self {
            mode,
            relationship: PrincipalRelationship::from_uids(principal_uid, daemon_uid),
        }
    }

    /// What the cell of the section 13 matrix means for this deployment.
    pub fn meaning(&self) -> &'static str {
        match (self.mode, self.relationship) {
            (AgentMode::SameUser, PrincipalRelationship::SharedUid) => {
                "the agent is fully the user; there is no process boundary (policy, session limits \
                 and audit only)"
            }
            (AgentMode::SameUser, PrincipalRelationship::DistinctUid) => {
                "the agent reaches human passkeys only through the daemon; a Unix boundary \
                 protects the backend, config and granted-rules store"
            }
            (AgentMode::Isolated, PrincipalRelationship::SharedUid) => {
                "separate passkeys, but the agent runs as the daemon's UID and can read the \
                 human store; separation is administrative only"
            }
            (AgentMode::Isolated, PrincipalRelationship::DistinctUid) => {
                "full isolation, the recommended strong mode"
            }
        }
    }

    /// The shared-UID `isolated` warning of section 13, `None` for every other cell.
    pub fn isolated_shared_uid_warning(&self) -> Option<String> {
        (self.mode == AgentMode::Isolated && self.relationship.is_shared_uid()).then(|| {
            "mode isolated with a shared-UID principal: the principal runs as the daemon's UID and \
             can read the human store, so separation is administrative only (ADR 0014 section \
             13); run the principal as a distinct user for full isolation"
                .to_string()
        })
    }

    /// The doctor checks for this profile: `deployment_axes` always, plus
    /// `isolated_shared_uid` (passing, with a `warning:` message, like the other doctor warnings)
    /// when the warning applies. `suffix` makes the names unique across profiles at startup.
    pub fn checks(&self, suffix: Option<&str>) -> Vec<DoctorCheck> {
        let name = |base: &str| match suffix {
            Some(s) => format!("{base}.{s}"),
            None => base.to_string(),
        };
        let mut checks = vec![DoctorCheck {
            name: name("deployment_axes"),
            passed: true,
            message: format!(
                "mode: {}, principal_relationship: {}; {}",
                self.mode,
                self.relationship,
                self.meaning()
            ),
        }];
        if let Some(warning) = self.isolated_shared_uid_warning() {
            checks.push(DoctorCheck {
                name: name("isolated_shared_uid"),
                passed: true,
                message: format!("warning: {warning}"),
            });
        }
        checks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAEMON: u32 = 1000;

    #[test]
    fn the_relationship_is_the_principal_uid_against_the_daemon_uid() {
        assert_eq!(
            PrincipalRelationship::from_uids(DAEMON, DAEMON),
            PrincipalRelationship::SharedUid
        );
        assert_eq!(
            PrincipalRelationship::from_uids(DAEMON + 1, DAEMON),
            PrincipalRelationship::DistinctUid
        );
        assert_eq!(
            PrincipalRelationship::from_uids(0, DAEMON),
            PrincipalRelationship::DistinctUid
        );
    }

    #[test]
    fn the_audit_strings_are_stable() {
        // E2E-32 and audit consumers match on these exact values.
        assert_eq!(PrincipalRelationship::SharedUid.as_str(), "shared-uid");
        assert_eq!(PrincipalRelationship::DistinctUid.as_str(), "distinct-uid");
        assert_eq!(PrincipalRelationship::SharedUid.to_string(), "shared-uid");
    }

    #[test]
    fn same_user_shared_uid_is_the_agent_being_the_user_without_a_warning() {
        let axes = DeploymentAxes::new(AgentMode::SameUser, DAEMON, DAEMON);
        assert_eq!(axes.relationship, PrincipalRelationship::SharedUid);
        assert_eq!(axes.isolated_shared_uid_warning(), None);
        let checks = axes.checks(None);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "deployment_axes");
        assert!(checks[0].passed);
        assert!(checks[0].message.contains("mode: same-user"));
        assert!(
            checks[0]
                .message
                .contains("principal_relationship: shared-uid")
        );
        assert!(checks[0].message.contains("fully the user"));
    }

    #[test]
    fn same_user_distinct_uid_has_a_unix_boundary_and_no_warning() {
        let axes = DeploymentAxes::new(AgentMode::SameUser, DAEMON + 1, DAEMON);
        assert_eq!(axes.isolated_shared_uid_warning(), None);
        let checks = axes.checks(None);
        assert_eq!(checks.len(), 1);
        assert!(checks[0].message.contains("mode: same-user"));
        assert!(
            checks[0]
                .message
                .contains("principal_relationship: distinct-uid")
        );
        assert!(checks[0].message.contains("Unix boundary"));
    }

    #[test]
    fn isolated_shared_uid_warns_that_separation_is_administrative_only() {
        let axes = DeploymentAxes::new(AgentMode::Isolated, DAEMON, DAEMON);
        let warning = axes.isolated_shared_uid_warning().expect("warning");
        assert!(warning.contains("administrative only"), "{warning}");
        let checks = axes.checks(None);
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].name, "deployment_axes");
        assert!(
            checks[0]
                .message
                .contains("principal_relationship: shared-uid")
        );
        assert_eq!(checks[1].name, "isolated_shared_uid");
        // A warning never makes the profile unhealthy.
        assert!(checks[1].passed);
        assert!(checks[1].message.starts_with("warning: "));
    }

    #[test]
    fn isolated_distinct_uid_is_the_recommended_strong_mode_without_a_warning() {
        let axes = DeploymentAxes::new(AgentMode::Isolated, DAEMON + 1, DAEMON);
        assert_eq!(axes.isolated_shared_uid_warning(), None);
        let checks = axes.checks(None);
        assert_eq!(checks.len(), 1);
        assert!(checks[0].message.contains("mode: isolated"));
        assert!(
            checks[0]
                .message
                .contains("principal_relationship: distinct-uid")
        );
        assert!(checks[0].message.contains("recommended strong mode"));
    }

    #[test]
    fn only_the_isolated_shared_uid_cell_warns() {
        for mode in [AgentMode::SameUser, AgentMode::Isolated] {
            for principal in [DAEMON, DAEMON + 1] {
                let axes = DeploymentAxes::new(mode, principal, DAEMON);
                let expected = mode == AgentMode::Isolated && principal == DAEMON;
                assert_eq!(
                    axes.isolated_shared_uid_warning().is_some(),
                    expected,
                    "{mode} principal {principal}"
                );
            }
        }
    }

    #[test]
    fn startup_check_names_carry_the_profile() {
        let axes = DeploymentAxes::new(AgentMode::Isolated, DAEMON, DAEMON);
        let names: Vec<_> = axes.checks(Some("p")).into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["deployment_axes.p", "isolated_shared_uid.p"]);
    }
}
