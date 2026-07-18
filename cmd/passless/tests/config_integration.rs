use std::fs;
use std::path::PathBuf;

use clap::Parser;
use tempfile::tempdir;

use passless_core::{AppConfig, Args, BackendConfig};

fn write_config(dir: &std::path::Path, content: &str) -> PathBuf {
    let path = dir.join("config.toml");
    fs::write(&path, content).unwrap();
    path
}

fn load_from_file(config_path: &std::path::Path) -> passless_core::Result<AppConfig> {
    let mut args = Args::try_parse_from([
        "passless",
        "--config-path",
        &config_path.display().to_string(),
    ])
    .unwrap();
    AppConfig::load(&mut args)
}

#[test]
fn valid_minimal_toml_loads_with_defaults() {
    let dir = tempdir().unwrap();
    let path = write_config(dir.path(), r#"backend_type = "local""#);
    let config = load_from_file(&path).unwrap();
    assert_eq!(config.backend_type, "local");
    assert!(config.security.always_uv);
    assert_eq!(config.pin.min_length, 4);
}

#[test]
fn unknown_top_level_field_is_silently_ignored() {
    let dir = tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r#"
backend_type = "local"
totally_unknown_field = "nope"
"#,
    );
    let config = load_from_file(&path).unwrap();
    assert_eq!(config.backend_type, "local");
}

#[test]
fn unknown_security_field_is_silently_ignored() {
    let dir = tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r#"
backend_type = "local"
[security]
bogus_key = true
"#,
    );
    let config = load_from_file(&path).unwrap();
    assert!(config.security.always_uv);
}

#[test]
fn unknown_pin_field_is_silently_ignored() {
    let dir = tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r#"
backend_type = "local"
[pin]
nope = 99
"#,
    );
    let config = load_from_file(&path).unwrap();
    assert_eq!(config.pin.min_length, 4);
}

#[test]
fn malformed_toml_returns_config_error() {
    let dir = tempdir().unwrap();
    let path = write_config(dir.path(), "this is not [valid toml {{");
    let result = load_from_file(&path);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("failed to parse config file"));
}

#[test]
fn invalid_backend_type_rejected_at_backend_resolution() {
    let dir = tempdir().unwrap();
    let path = write_config(dir.path(), r#"backend_type = "faketype""#);
    let config = load_from_file(&path).unwrap();
    let result = config.backend();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("faketype"));
}

#[test]
fn pin_validation_boundaries() {
    let dir = tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r#"
backend_type = "local"
[pin]
min_length = 2
"#,
    );
    let config = load_from_file(&path).unwrap();
    assert!(config.validate().is_err());

    let path2 = write_config(
        dir.path(),
        r#"
backend_type = "local"
[pin]
max_retries = 0
"#,
    );
    let config2 = load_from_file(&path2).unwrap();
    assert!(config2.validate().is_err());
}

#[test]
fn backend_state_path_canonicalization_is_deterministic() {
    let dir = tempdir().unwrap();
    let sub = dir.path().join("subdir");
    fs::create_dir_all(&sub).unwrap();

    let b1 = BackendConfig::Local {
        path: sub.display().to_string(),
    };
    let b2 = BackendConfig::Local {
        path: sub.join(".").display().to_string(),
    };
    assert_eq!(b1.state_path(), b2.state_path());
}

#[test]
fn different_backends_produce_different_state_paths() {
    let dir = tempdir().unwrap();
    let p = dir.path().display().to_string();
    let local = BackendConfig::Local { path: p.clone() };
    let pass = BackendConfig::Pass {
        store_path: p.clone(),
        path: "fido2".into(),
        gpg_backend: "gnupg-bin".into(),
    };
    assert_ne!(local.state_path(), pass.state_path());
}

#[test]
fn pass_state_path_differs_by_subpath() {
    let a = BackendConfig::Pass {
        store_path: "/tmp/store".into(),
        path: "fido2".into(),
        gpg_backend: "gnupg-bin".into(),
    };
    let b = BackendConfig::Pass {
        store_path: "/tmp/store".into(),
        path: "other".into(),
        gpg_backend: "gnupg-bin".into(),
    };
    assert_ne!(a.state_path(), b.state_path());
}

#[test]
fn state_display_matches_human_expectations() {
    let local = BackendConfig::Local {
        path: "/tmp/x".into(),
    };
    assert_eq!(local.state_display(), "/tmp/x");

    let pass = BackendConfig::Pass {
        store_path: "/store".into(),
        path: "fido2".into(),
        gpg_backend: "gnupg-bin".into(),
    };
    assert_eq!(pass.state_display(), "/store/fido2");
}

#[test]
fn cli_overrides_config_file() {
    let dir = tempdir().unwrap();
    let path = write_config(dir.path(), r#"backend_type = "pass""#);
    let mut args = Args::try_parse_from([
        "passless",
        "--config-path",
        &path.display().to_string(),
        "--backend-type",
        "local",
    ])
    .unwrap();
    let config = AppConfig::load(&mut args).unwrap();
    assert_eq!(config.backend_type, "local");
}

#[test]
fn missing_config_file_falls_back_to_defaults() {
    let mut args =
        Args::try_parse_from(["passless", "--config-path", "/nonexistent/path/config.toml"])
            .unwrap();
    let config = AppConfig::load(&mut args).unwrap();
    assert_eq!(config.backend_type, "pass");
}

#[test]
fn config_print_produces_valid_toml() {
    let mut args = Args::parse_from(["passless"]);
    let config = AppConfig::from(&mut args.config);
    let toml_str = config.to_toml_with_comments();
    assert!(toml_str.contains("backend_type"));
    assert!(toml_str.contains("[security]"));
    assert!(toml_str.contains("[pin]"));
}

#[test]
fn error_format_cli_produces_actionable_messages() {
    let err = passless_core::Error::AlreadyRunning {
        path: PathBuf::from("/tmp/test"),
    };
    let formatted = err.format_cli();
    assert!(formatted.contains("/tmp/test"));
    assert!(formatted.contains("systemctl"));
}

#[test]
fn symlinked_paths_resolve_to_same_state_identity() {
    let dir = tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir_all(&real).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let b_real = BackendConfig::Local {
        path: real.display().to_string(),
    };
    let b_link = BackendConfig::Local {
        path: link.display().to_string(),
    };
    assert_eq!(b_real.state_path(), b_link.state_path());
}
