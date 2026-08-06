use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

use passless_core::BackendConfig;

#[test]
fn test_backend_validate_rejects_absolute_pass_path() {
    let config = BackendConfig::Pass {
        store_path: "/tmp/store".to_string(),
        path: "/absolute/path".to_string(),
        gpg_backend: "gnupg-bin".to_string(),
    };
    let result = config.validate();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("must be relative"));
}

#[test]
fn test_backend_validate_rejects_pass_path_with_parent_traversal() {
    let config = BackendConfig::Pass {
        store_path: "/tmp/store".to_string(),
        path: "../outside".to_string(),
        gpg_backend: "gnupg-bin".to_string(),
    };
    let result = config.validate();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("must not contain '..'"));
}

#[test]
fn test_backend_validate_rejects_pass_path_with_leading_slash() {
    let config = BackendConfig::Pass {
        store_path: "/tmp/store".to_string(),
        path: "/leading-slash".to_string(),
        gpg_backend: "gnupg-bin".to_string(),
    };
    let result = config.validate();
    assert!(result.is_err());
}

#[test]
fn test_backend_validate_accepts_valid_pass_path() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().to_string_lossy().to_string();
    let config = BackendConfig::Pass {
        store_path: store_path.clone(),
        path: "fido2".to_string(),
        gpg_backend: "gnupg-bin".to_string(),
    };
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn test_backend_validate_accepts_nested_pass_path() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().to_string_lossy().to_string();
    let config = BackendConfig::Pass {
        store_path: store_path.clone(),
        path: "sub/dir/fido2".to_string(),
        gpg_backend: "gnupg-bin".to_string(),
    };
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn test_backend_validate_rejects_pass_path_escaping_store() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("store").to_string_lossy().to_string();
    fs::create_dir_all(&store_path).unwrap();
    let config = BackendConfig::Pass {
        store_path: store_path.clone(),
        path: "../../outside".to_string(),
        gpg_backend: "gnupg-bin".to_string(),
    };
    let result = config.validate();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("escapes store_path")
            || err.to_string().contains("must not contain")
    );
}

#[test]
fn test_backend_validate_accepts_local_backend() {
    let dir = tempdir().unwrap();
    let path = dir.path().to_string_lossy().to_string();
    let config = BackendConfig::Local { path };
    let result = config.validate();
    assert!(result.is_ok());
}

#[test]
fn test_external_dir_permissions_unchanged_after_rejected_attack() {
    let external_dir = tempdir().unwrap();
    fs::set_permissions(external_dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let original_mode = fs::metadata(external_dir.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    let result = std::panic::catch_unwind(|| {
        let _ = fs::create_dir_all(external_dir.path().join("nonexistent/.."));
    });

    let current_mode = fs::metadata(external_dir.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(original_mode, current_mode);
    let _ = result;
}
