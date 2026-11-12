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
fn a_wildcard_with_credential_refs_is_an_error_and_a_doctor_failure() {
    // The case `doctor --agents` used to pass without a word.
    let fixture = Fixture::new();
    let path = fixture.write(
        "acknowledge_global_same_user = [\"p\"]",
        &profile(
            &format!("credential_refs = [\"{REF}\"]"),
            "rp_id = \"*\"\nauthenticate = \"allow\"",
        ),
    );
    let config = load(&path);
    let err = error_of(&path);
    assert!(
        err.contains("wildcard RP scope '*' requires credential_refs to be omitted"),
        "{err}"
    );
    let checks = config_checks(check(&config));
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].name, "config");
    assert!(!checks[0].passed, "{:?}", checks[0]);
    assert!(
        checks[0].message.contains("credential_refs"),
        "{:?}",
        checks[0]
    );
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
