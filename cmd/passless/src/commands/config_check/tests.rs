use super::*;

use clap::Parser;

use crate::agent::doctor_agents::config_checks;

const REF: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A configuration file in a temporary directory: the daemon's own loading, with `agents` and the
/// profile appended to a base that has private, existing directories.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn write(&self, agents_extra: &str, profile: &str) -> PathBuf {
        let root = self.dir.path();
        let path = root.join("config.toml");
        std::fs::write(
            &path,
            format!(
                "backend_type = \"local\"\n[local]\npath = \"{root}/human\"\n\n\
                 [agents]\nenabled = true\naudit_path = \"{root}/audit\"\nstate_dir = \"{root}/state\"\n\
                 {agents_extra}\n{profile}\n",
                root = root.display()
            ),
        )
        .unwrap();
        path
    }
}

fn load(path: &Path) -> AppConfig {
    let mut args = Args::try_parse_from(["passless", "-c", path.to_str().unwrap()]).unwrap();
    AppConfig::load(&mut args).unwrap()
}

use std::path::Path;

fn profile(extra: &str, rules: &str) -> String {
    format!(
        "[agents.profiles.p]\nmode = \"same-user\"\nprincipal_user = \"agent\"\n{extra}\n\
         [[agents.profiles.p.rules]]\n{rules}\n"
    )
}

fn error_of(path: &Path) -> String {
    check(&load(path)).unwrap_err().to_string()
}

#[test]
fn a_valid_configuration_passes_without_warnings() {
    let fixture = Fixture::new();
    let path = fixture.write(
        "",
        &profile("", "rp_id = \"example.com\"\nauthenticate = \"allow\""),
    );
    assert_eq!(check(&load(&path)).unwrap(), Checked::default());
}

#[test]
fn a_wildcard_with_credential_refs_is_valid() {
    // ADR 0014 amendment change 1: the pins constrain the exact rules; `*` discovers.
    let fixture = Fixture::new();
    let path = fixture.write(
        "acknowledge_global_same_user = [\"p\"]",
        &profile(
            &format!("credential_refs = [\"{REF}\"]"),
            "rp_id = \"*\"\nauthenticate = \"request\"\n\n\
             [[agents.profiles.p.rules]]\nrp_id = \"github.com\"\nauthenticate = \"allow\"",
        ),
    );
    assert_eq!(check(&load(&path)).unwrap(), Checked::default());
}

#[test]
fn wildcard_registration_rules_flow_through_the_startup_check() {
    let fixture = Fixture::new();
    let wildcard_register = |register: &str| {
        profile(
            "",
            &format!("rp_id = \"*\"\nauthenticate = \"request\"\nregister = \"{register}\""),
        )
    };
    let all_but_global = "acknowledge_global_same_user = [\"p\"]\n\
                          acknowledge_same_user_registration = [\"p\"]";

    // `request` without `acknowledge_global_registration`: refused, naming it.
    let path = fixture.write(all_but_global, &wildcard_register("request"));
    let err = error_of(&path);
    assert!(
        err.contains("agents.acknowledge_global_registration"),
        "{err}"
    );
    let checks = config_checks(check(&load(&path)));
    assert!(!checks[0].passed, "{checks:?}");

    // `allow` on `*`: refused even with every acknowledgement.
    let all = format!("{all_but_global}\nacknowledge_global_registration = [\"p\"]");
    let path = fixture.write(&all, &wildcard_register("allow"));
    assert!(
        error_of(&path).contains("must not have register = \"allow\""),
        "{}",
        error_of(&path)
    );

    // `request` with all three: valid.
    let path = fixture.write(&all, &wildcard_register("request"));
    assert_eq!(check(&load(&path)).unwrap(), Checked::default());

    // Out-of-range limits are errors.
    let path = fixture.write(
        &all,
        &profile(
            "max_wildcard_registrations = 33",
            "rp_id = \"*\"\nauthenticate = \"request\"\nregister = \"request\"",
        ),
    );
    assert!(error_of(&path).contains("max_wildcard_registrations must be between 1 and 32"));
}

#[test]
fn wildcard_registration_advice_is_reported_as_warnings() {
    let fixture = Fixture::new();
    let path = fixture.write(
        "acknowledge_global_registration = [\"p\"]",
        &profile(
            "wildcard_registration_prompts_per_day = 2",
            "rp_id = \"example.com\"\nauthenticate = \"allow\"",
        ),
    );
    let checked = check(&load(&path)).unwrap();
    assert_eq!(checked.warnings.len(), 2, "{checked:?}");
    assert!(checked.warnings[0].contains("wildcard_registration_prompts_per_day has no effect"));
    assert!(checked.warnings[1].contains("acknowledgement is stale"));
}

#[test]
fn the_acknowledgements_are_required() {
    let fixture = Fixture::new();
    let wildcard = fixture.write("", &profile("", "rp_id = \"*\"\nauthenticate = \"allow\""));
    assert!(error_of(&wildcard).contains("acknowledge_global_same_user"));

    let register = fixture.write(
        "",
        &profile(
            "",
            "rp_id = \"example.com\"\nauthenticate = \"allow\"\nregister = \"allow\"",
        ),
    );
    assert!(error_of(&register).contains("acknowledge_same_user_registration"));
    let acknowledged = fixture.write(
        "acknowledge_same_user_registration = [\"p\"]",
        &profile(
            "",
            "rp_id = \"example.com\"\nauthenticate = \"allow\"\nregister = \"allow\"",
        ),
    );
    check(&load(&acknowledged)).unwrap();
}

#[test]
fn an_audit_path_whose_parent_is_missing_is_an_error() {
    // The daemon creates only the last component of `audit_path`.
    let fixture = Fixture::new();
    let path = fixture.write(
        "",
        &profile("", "rp_id = \"example.com\"\nauthenticate = \"allow\""),
    );
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("/audit\"", "/missing/audit\"");
    std::fs::write(&path, text).unwrap();
    let err = error_of(&path);
    assert!(
        err.contains("agents.audit_path") && err.contains("parent directory"),
        "{err}"
    );

    // An existing audit directory must be private.
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("/missing/audit\"", "/open\"");
    std::fs::write(&path, text).unwrap();
    let open = fixture.dir.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    assert!(
        error_of(&path).contains("mode"),
        "a group-readable audit directory"
    );
}

#[test]
fn deprecations_are_warnings_and_disabled_agents_are_not_validated() {
    let fixture = Fixture::new();
    let path = fixture.write(
        "",
        &profile("", "rp_id = \"example.com\"\nauthenticate = \"autonomous\""),
    );
    let checked = check(&load(&path)).unwrap();
    assert_eq!(checked.warnings.len(), 1, "{checked:?}");
    assert!(checked.warnings[0].contains("deprecated"), "{checked:?}");
    let checks = config_checks(Ok(checked));
    assert!(checks.iter().all(|c| c.passed));
    assert!(
        checks[1].message.starts_with("warning: "),
        "{:?}",
        checks[1]
    );

    // The daemon skips the profile rules when agents are off; the check says so.
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("enabled = true", "enabled = false");
    std::fs::write(&path, text).unwrap();
    let checked = check(&load(&path)).unwrap();
    assert!(checked.warnings.is_empty());
    assert!(checked.notes[0].contains("not validated"), "{checked:?}");
}

#[test]
fn a_config_file_named_on_purpose_must_exist() {
    let mut args = Args::try_parse_from(["passless"]).unwrap();
    let err = dispatch(&mut args, Some(PathBuf::from("/nonexistent/passless.toml")))
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not exist"), "{err}");
}

#[test]
fn a_file_that_does_not_parse_is_an_error() {
    let fixture = Fixture::new();
    let path = fixture.dir.path().join("config.toml");
    std::fs::write(&path, "backend_type = ").unwrap();
    let mut args = Args::try_parse_from(["passless"]).unwrap();
    assert!(dispatch(&mut args, Some(path)).is_err());
}
