//! `credProtect` against the agent's evidence (ADR 0014 sections 7 and 10.2, invariant 15).
//!
//! The stored level decides whether the credential may be used without user verification:
//!
//! | Level | Meaning | Needs UV when |
//! |---|---|---|
//! | 1 `userVerificationOptional` (or none) | no constraint | never |
//! | 2 `userVerificationOptionalWithCredentialIDList` | usable without UV only when the request names the credential in `allowCredentials` | the request has no `allowCredentials` |
//! | 3 `userVerificationRequired` | always needs UV | always |
//!
//! Agent evidence is UV = true under `allow` (the operator chose autonomy; the audit labels it
//! `agent`), so every level is satisfied on the agent path today. The check is still evaluated,
//! not skipped, so that evidence which ever carried no UV could not weaken a protected
//! credential (invariant 15). An unknown level is treated as 3, the strictest.

/// Whether a credential stored with `level` may be used when the ceremony has user verification
/// `uv` and the request does (`has_allow_list`) or does not name credentials.
pub fn satisfied(level: Option<u8>, uv: bool, has_allow_list: bool) -> bool {
    match level {
        None | Some(1) => true,
        Some(2) => uv || has_allow_list,
        Some(_) => uv,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_one_and_no_level_never_need_uv() {
        for level in [None, Some(1)] {
            for uv in [false, true] {
                for list in [false, true] {
                    assert!(satisfied(level, uv, list), "{level:?} uv={uv} list={list}");
                }
            }
        }
    }

    #[test]
    fn level_two_needs_uv_unless_the_request_names_the_credential() {
        // Without allowCredentials the credential is discoverable only with UV.
        assert!(!satisfied(Some(2), false, false));
        assert!(satisfied(Some(2), true, false));
        // With allowCredentials the credential ID list stands in for UV.
        assert!(satisfied(Some(2), false, true));
        assert!(satisfied(Some(2), true, true));
    }

    #[test]
    fn level_three_needs_uv_with_or_without_allow_credentials() {
        assert!(!satisfied(Some(3), false, false));
        assert!(!satisfied(Some(3), false, true));
        assert!(satisfied(Some(3), true, false));
        assert!(satisfied(Some(3), true, true));
    }

    #[test]
    fn an_unknown_level_is_as_strict_as_level_three() {
        for level in [0u8, 4, 255] {
            assert!(!satisfied(Some(level), false, true));
            assert!(satisfied(Some(level), true, false));
        }
    }

    #[test]
    fn agent_evidence_satisfies_every_level_with_or_without_allow_credentials() {
        // `allow` gives UV = true (sign.rs): the operator's choice is what satisfies level 3.
        for level in [None, Some(1), Some(2), Some(3)] {
            for list in [false, true] {
                assert!(satisfied(level, true, list), "{level:?} list={list}");
            }
        }
    }
}
