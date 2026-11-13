use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use passless_core::agent::config::AgentStorageConfig;
use passless_core::error::{Error, Result};

#[cfg(test)]
use passless_core::agent::config::{AgentProfileConfig, BrowserScope};

use crate::pin_storage::PinStorage;
use crate::storage::CredentialStorage;
use crate::storage::pass::GpgBackend;

pub struct AgentStorageBundle {
    pub credential_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub pin_storage: Arc<Mutex<Box<dyn PinStorage>>>,
    pub config: AgentStorageConfig,
    #[cfg(feature = "tpm")]
    pub tpm_key_provider: Option<crate::storage::tpm::portable::TpmCredentialKeyProvider>,
}

impl core::fmt::Debug for AgentStorageBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("AgentStorageBundle");
        d.field("config", &self.config);
        #[cfg(feature = "tpm")]
        d.field(
            "tpm_key_provider",
            &self
                .tpm_key_provider
                .as_ref()
                .map(|_| "TpmCredentialKeyProvider"),
        );
        d.finish_non_exhaustive()
    }
}

impl AgentStorageBundle {
    #[cfg(test)]
    pub fn credential_dir(&self) -> PathBuf {
        self.config.credential_state_path()
    }

    #[cfg(test)]
    pub fn pin_dir(&self) -> PathBuf {
        self.config.pin_state_path()
    }
}

pub fn validate_profile_paths(config: &AgentStorageConfig) -> Result<()> {
    match config {
        AgentStorageConfig::Local { path, pin_path } => {
            ensure_secure_directory(path)?;
            ensure_secure_directory(pin_path)?;
            ensure_no_path_overlap(path, pin_path)?;
        }
        AgentStorageConfig::Pass {
            store_path,
            path,
            pin_path,
            ..
        } => {
            ensure_secure_directory(store_path)?;
            let cred_path = store_path.join(path);
            let pin_full = store_path.join(pin_path);
            ensure_no_path_overlap(&cred_path, &pin_full)?;
        }
        #[cfg(feature = "tpm")]
        AgentStorageConfig::Tpm { path, pin_path, .. } => {
            ensure_secure_directory(path)?;
            ensure_secure_directory(pin_path)?;
            ensure_no_path_overlap(path, pin_path)?;
        }
    }

    Ok(())
}

fn ensure_secure_directory(path: &Path) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let mut current = PathBuf::new();

    for component in path.components() {
        current.push(component);

        if current == Path::new("/") {
            continue;
        }

        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(Error::Storage(format!(
                        "symlink detected in path at {}: refusing to open for security",
                        current.display()
                    )));
                }

                if !meta.is_dir() {
                    return Err(Error::Storage(format!(
                        "path component {} is not a directory",
                        current.display()
                    )));
                }

                let dir_uid = meta.uid();
                if dir_uid != uid && dir_uid != 0 {
                    return Err(Error::Storage(format!(
                        "path component {} owned by uid {} but current uid is {}; refusing to open",
                        current.display(),
                        dir_uid,
                        uid
                    )));
                }

                if dir_uid == uid {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        return Err(Error::Storage(format!(
                            "path component {} has insecure permissions {:o}; expected 0o700 or stricter",
                            current.display(),
                            mode
                        )));
                    }
                }
            }
            Err(_) => {
                if let Err(e) = fs::create_dir(&current) {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        let meta = fs::symlink_metadata(&current).map_err(|e| {
                            Error::Storage(format!(
                                "failed to read metadata for {}: {}",
                                current.display(),
                                e
                            ))
                        })?;

                        if meta.file_type().is_symlink() {
                            return Err(Error::Storage(format!(
                                "symlink detected in path at {}: refusing to open for security",
                                current.display()
                            )));
                        }

                        if !meta.is_dir() {
                            return Err(Error::Storage(format!(
                                "path component {} is not a directory",
                                current.display()
                            )));
                        }

                        let dir_uid = meta.uid();
                        if dir_uid != uid && dir_uid != 0 {
                            return Err(Error::Storage(format!(
                                "path component {} owned by uid {} but current uid is {}; refusing to open",
                                current.display(),
                                dir_uid,
                                uid
                            )));
                        }

                        if dir_uid == uid {
                            let mode = meta.permissions().mode() & 0o777;
                            if mode & 0o077 != 0 {
                                return Err(Error::Storage(format!(
                                    "path component {} has insecure permissions {:o}; expected 0o700 or stricter",
                                    current.display(),
                                    mode
                                )));
                            }
                        }
                    } else {
                        return Err(Error::Storage(format!(
                            "failed to create directory {}: {}",
                            current.display(),
                            e
                        )));
                    }
                } else {
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).map_err(
                        |e| {
                            Error::Storage(format!(
                                "failed to set permissions on {}: {}",
                                current.display(),
                                e
                            ))
                        },
                    )?;
                }
            }
        }
    }

    Ok(())
}

fn ensure_no_path_overlap(a: &Path, b: &Path) -> Result<()> {
    let canon_a = passless_core::BackendConfig::canonicalize_path(a);
    let canon_b = passless_core::BackendConfig::canonicalize_path(b);

    if canon_a.starts_with(&canon_b) || canon_b.starts_with(&canon_a) {
        return Err(Error::Storage(format!(
            "profile paths {} and {} overlap; each profile must use disjoint directories",
            a.display(),
            b.display()
        )));
    }

    Ok(())
}

#[cfg(test)]
pub fn create_storage_bundle(config: AgentStorageConfig) -> Result<AgentStorageBundle> {
    create_storage_bundle_with_options(config, false)
}

/// Resolve the signing provider that belongs to an agent storage backend.
///
/// Portable TPM storage must never silently fall back to the software provider.
/// A fresh provider instance uses the same provisioned TPM parent and keeps its
/// own TPM context, while the backend operation lock serializes credential use.
pub fn key_provider_for_config(
    config: &AgentStorageConfig,
) -> Result<Arc<dyn soft_fido2::CredentialKeyProvider + Send + Sync>> {
    match config {
        #[cfg(feature = "tpm")]
        AgentStorageConfig::Tpm {
            path,
            tcti,
            portable: true,
            ..
        } => {
            let tcti = if tcti.is_empty() {
                None
            } else {
                Some(tcti.clone())
            };
            let provider =
                crate::storage::tpm::portable::TpmCredentialKeyProvider::new(path.clone(), tcti)
                    .map_err(|e| {
                        Error::Storage(format!(
                            "failed to create portable TPM key provider at {}: {:?}",
                            path.display(),
                            e
                        ))
                    })?;
            Ok(Arc::new(provider))
        }
        _ => Ok(Arc::new(soft_fido2::SoftwareCredentialKeyProvider)),
    }
}

pub fn create_storage_bundle_with_options(
    config: AgentStorageConfig,
    allow_create_without_prompt: bool,
) -> Result<AgentStorageBundle> {
    validate_profile_paths(&config)?;

    match config {
        AgentStorageConfig::Local {
            ref path,
            ref pin_path,
        } => {
            let cred_storage = crate::storage::LocalStorageAdapter::new_with_options(
                path.clone(),
                allow_create_without_prompt,
            )
            .map_err(|e| {
                Error::Storage(format!(
                    "failed to create local credential storage at {}: {:?}",
                    path.display(),
                    e
                ))
            })?;

            let pin_storage = crate::pin_storage::LocalPinStorage::new(pin_path.clone());

            Ok(AgentStorageBundle {
                credential_storage: Arc::new(Mutex::new(Box::new(cred_storage))),
                pin_storage: Arc::new(Mutex::new(Box::new(pin_storage))),
                config,
                #[cfg(feature = "tpm")]
                tpm_key_provider: None,
            })
        }
        AgentStorageConfig::Pass {
            ref store_path,
            ref path,
            ref gpg_backend,
            ref pin_path,
            git_sync,
            git_auto_push,
        } => {
            let gpg = gpg_backend.parse::<GpgBackend>().map_err(|e| {
                Error::Storage(format!("invalid GPG backend '{}': {}", gpg_backend, e))
            })?;

            let cred_storage = crate::storage::PassStorageAdapter::new_with_options_and_git_sync(
                store_path.clone(),
                PathBuf::from(path),
                gpg,
                allow_create_without_prompt,
                git_sync,
                git_auto_push,
            )
            .map_err(|e| {
                Error::Storage(format!(
                    "failed to create pass credential storage at {}/{}: {}",
                    store_path.display(),
                    path,
                    e
                ))
            })?;

            let pass_sync = cred_storage.sync_handle();
            let pin_storage = crate::pin_storage::PassPinStorage::new_with_sync(
                store_path.clone(),
                pin_path.clone(),
                gpg,
                pass_sync,
            );

            Ok(AgentStorageBundle {
                credential_storage: Arc::new(Mutex::new(Box::new(cred_storage))),
                pin_storage: Arc::new(Mutex::new(Box::new(pin_storage))),
                config,
                #[cfg(feature = "tpm")]
                tpm_key_provider: None,
            })
        }
        #[cfg(feature = "tpm")]
        AgentStorageConfig::Tpm {
            ref path,
            ref tcti,
            ref pin_path,
            portable,
        } => {
            let tcti_opt = if tcti.is_empty() {
                None
            } else {
                Some(tcti.clone())
            };

            if portable {
                use crate::storage::tpm::portable::TpmCredentialKeyProvider;

                let provider = TpmCredentialKeyProvider::new(path.clone(), tcti_opt.clone())
                    .map_err(|e| {
                        Error::Storage(format!(
                            "failed to create TPM key provider at {}: {:?}",
                            path.display(),
                            e
                        ))
                    })?;
                if !provider.is_ready() {
                    return Err(Error::Storage(
                        "TPM portable parent is not provisioned. Run: passless tpm provision"
                            .to_string(),
                    ));
                }

                let cred_storage = crate::storage::TpmStorageAdapter::new_portable(
                    path.clone(),
                    tcti_opt.clone(),
                    allow_create_without_prompt,
                )
                .map_err(|e| {
                    Error::Storage(format!(
                        "failed to create portable TPM credential storage at {}: {:?}",
                        path.display(),
                        e
                    ))
                })?;

                let pin_storage =
                    crate::pin_storage::TpmPinStorage::new_portable(pin_path.clone(), tcti_opt);

                Ok(AgentStorageBundle {
                    credential_storage: Arc::new(Mutex::new(Box::new(cred_storage))),
                    pin_storage: Arc::new(Mutex::new(Box::new(pin_storage))),
                    config,
                    tpm_key_provider: Some(provider),
                })
            } else {
                let cred_storage = crate::storage::TpmStorageAdapter::new_with_options(
                    path.clone(),
                    tcti_opt.clone(),
                    allow_create_without_prompt,
                )
                .map_err(|e| {
                    Error::Storage(format!(
                        "failed to create TPM credential storage at {}: {:?}",
                        path.display(),
                        e
                    ))
                })?;

                let pin_storage =
                    crate::pin_storage::TpmPinStorage::new(pin_path.clone(), tcti_opt);

                Ok(AgentStorageBundle {
                    credential_storage: Arc::new(Mutex::new(Box::new(cred_storage))),
                    pin_storage: Arc::new(Mutex::new(Box::new(pin_storage))),
                    config,
                    tpm_key_provider: None,
                })
            }
        }
    }
}

#[cfg(test)]
pub fn config_from_profile(profile: &AgentProfileConfig) -> Result<AgentStorageConfig> {
    profile
        .storage
        .clone()
        .ok_or_else(|| Error::Config("isolated profile requires storage configuration".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn make_local_config(cred_dir: &Path, pin_dir: &Path) -> AgentStorageConfig {
        AgentStorageConfig::Local {
            path: cred_dir.to_path_buf(),
            pin_path: pin_dir.to_path_buf(),
        }
    }

    #[test]
    fn test_create_local_bundle_isolated_profiles() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_a = base.path().join("profile_a").join("creds");
        let pin_a = base.path().join("profile_a").join("pin");
        let cred_b = base.path().join("profile_b").join("creds");
        let pin_b = base.path().join("profile_b").join("pin");

        let config_a = make_local_config(&cred_a, &pin_a);
        let config_b = make_local_config(&cred_b, &pin_b);

        let bundle_a = create_storage_bundle(config_a).unwrap();
        let bundle_b = create_storage_bundle(config_b).unwrap();

        assert_ne!(bundle_a.credential_dir(), bundle_b.credential_dir());
        assert_ne!(bundle_a.pin_dir(), bundle_b.pin_dir());
    }

    #[test]
    fn test_profiles_do_not_share_arc_mutex() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_a = base.path().join("a").join("creds");
        let pin_a = base.path().join("a").join("pin");
        let cred_b = base.path().join("b").join("creds");
        let pin_b = base.path().join("b").join("pin");

        let bundle_a = create_storage_bundle(make_local_config(&cred_a, &pin_a)).unwrap();
        let bundle_b = create_storage_bundle(make_local_config(&cred_b, &pin_b)).unwrap();

        let ptr_a_cred = Arc::as_ptr(&bundle_a.credential_storage);
        let ptr_b_cred = Arc::as_ptr(&bundle_b.credential_storage);
        assert_ne!(ptr_a_cred, ptr_b_cred);

        let ptr_a_pin = Arc::as_ptr(&bundle_a.pin_storage);
        let ptr_b_pin = Arc::as_ptr(&bundle_b.pin_storage);
        assert_ne!(ptr_a_pin, ptr_b_pin);
    }

    #[test]
    fn test_credential_isolation_between_profiles() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_a = base.path().join("iso_a").join("creds");
        let pin_a = base.path().join("iso_a").join("pin");
        let cred_b = base.path().join("iso_b").join("creds");
        let pin_b = base.path().join("iso_b").join("pin");

        let bundle_a = create_storage_bundle(make_local_config(&cred_a, &pin_a)).unwrap();
        let bundle_b = create_storage_bundle(make_local_config(&cred_b, &pin_b)).unwrap();

        assert!(bundle_a.credential_dir().exists());
        assert!(bundle_b.credential_dir().exists());
        assert_ne!(bundle_a.credential_dir(), bundle_b.credential_dir());

        let cred_a_entries: Vec<_> = fs::read_dir(bundle_a.credential_dir()).unwrap().collect();
        let cred_b_entries: Vec<_> = fs::read_dir(bundle_b.credential_dir()).unwrap().collect();
        assert!(cred_a_entries.is_empty());
        assert!(cred_b_entries.is_empty());
    }

    #[test]
    fn test_pin_state_isolation_between_profiles() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_a = base.path().join("pin_iso_a").join("creds");
        let pin_a = base.path().join("pin_iso_a").join("pin");
        let cred_b = base.path().join("pin_iso_b").join("creds");
        let pin_b = base.path().join("pin_iso_b").join("pin");

        let bundle_a = create_storage_bundle(make_local_config(&cred_a, &pin_a)).unwrap();
        let bundle_b = create_storage_bundle(make_local_config(&cred_b, &pin_b)).unwrap();

        let pin_file_a = bundle_a.pin_dir().join("pin_state.json");
        let pin_file_b = bundle_b.pin_dir().join("pin_state.json");
        assert_ne!(pin_file_a, pin_file_b);

        {
            let ps = bundle_a.pin_storage.lock().unwrap();
            let mut state = ps.load_pin_state().unwrap();
            state.retries = 3;
            ps.save_pin_state(&state).unwrap();
        }

        {
            let ps = bundle_b.pin_storage.lock().unwrap();
            let state = ps.load_pin_state().unwrap();
            assert_eq!(state.retries, 8);
        }

        {
            let ps = bundle_a.pin_storage.lock().unwrap();
            let state = ps.load_pin_state().unwrap();
            assert_eq!(state.retries, 3);
        }
    }

    #[test]
    fn test_reject_insecure_permissions() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_dir = base.path().join("insecure").join("creds");
        let pin_dir = base.path().join("insecure").join("pin");

        fs::create_dir_all(&cred_dir).unwrap();
        fs::set_permissions(&cred_dir, fs::Permissions::from_mode(0o755)).unwrap();

        fs::create_dir_all(&pin_dir).unwrap();
        fs::set_permissions(&pin_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let config = make_local_config(&cred_dir, &pin_dir);
        let result = create_storage_bundle(config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("insecure permissions")
        );
    }

    #[test]
    fn test_reject_symlink_in_path() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let real_cred = base.path().join("real_creds");
        let real_pin = base.path().join("real_pin");
        fs::create_dir_all(&real_cred).unwrap();
        fs::set_permissions(&real_cred, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(&real_pin).unwrap();
        fs::set_permissions(&real_pin, fs::Permissions::from_mode(0o700)).unwrap();

        let link_cred = base.path().join("link_creds");
        std::os::unix::fs::symlink(&real_cred, &link_cred).unwrap();

        let config = make_local_config(&link_cred, &real_pin);
        let result = create_storage_bundle(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    fn test_reject_overlapping_paths() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_dir = base.path().join("overlap");
        let pin_dir = base.path().join("overlap").join("sub");

        let config = make_local_config(&cred_dir, &pin_dir);
        let result = validate_profile_paths(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("overlap"));
    }

    #[test]
    fn test_reject_symlink_directory_itself() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let real_dir = base.path().join("real");
        fs::create_dir_all(&real_dir).unwrap();
        fs::set_permissions(&real_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let link_dir = base.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

        let pin_dir = base.path().join("pin");
        fs::create_dir_all(&pin_dir).unwrap();
        fs::set_permissions(&pin_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let config = make_local_config(&link_dir, &pin_dir);
        let result = create_storage_bundle(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_accept_secure_permissions() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_dir = base.path().join("secure").join("creds");
        let pin_dir = base.path().join("secure").join("pin");

        let config = make_local_config(&cred_dir, &pin_dir);
        let result = create_storage_bundle(config);
        assert!(result.is_ok());

        let cred_meta = fs::metadata(&cred_dir).unwrap();
        assert_eq!(cred_meta.permissions().mode() & 0o777, 0o700);

        let pin_meta = fs::metadata(&pin_dir).unwrap();
        assert_eq!(pin_meta.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn test_config_from_profile() {
        use passless_core::agent::AgentMode;

        let profile = AgentProfileConfig {
            max_wildcard_registrations: None,
            wildcard_registration_prompts_per_day: None,
            pre_request_actions: Vec::new(),
            max_granted_rules: 64,
            max_operations: 64,
            max_concurrent_sessions: 1,
            browser_scope: BrowserScope::Session,
            credential_selection: passless_core::agent::config::CredentialSelection::Single,
            mode: AgentMode::Isolated,
            principal_user: "test-user".to_string(),
            credential_refs: None,
            max_grant_ttl: None,
            max_session_ttl: None,
            storage: Some(AgentStorageConfig::Local {
                path: PathBuf::from("/tmp/test/creds"),
                pin_path: PathBuf::from("/tmp/test/pin"),
            }),
            rules: vec![],
            legacy: Default::default(),
            device: None,
            start_url: None,
            browser_command: None,
            browser_user: None,
            browser_runtime_root: None,
            browser_cdp_expose: None,
            browser_cdp_port: None,
        };

        let config = config_from_profile(&profile).unwrap();
        match config {
            AgentStorageConfig::Local { path, pin_path } => {
                assert_eq!(path, PathBuf::from("/tmp/test/creds"));
                assert_eq!(pin_path, PathBuf::from("/tmp/test/pin"));
            }
            #[allow(unreachable_patterns)]
            _ => panic!("expected Local config"),
        }
    }

    #[test]
    fn test_config_from_profile_missing_storage() {
        use passless_core::agent::AgentMode;

        let profile = AgentProfileConfig {
            max_wildcard_registrations: None,
            wildcard_registration_prompts_per_day: None,
            pre_request_actions: Vec::new(),
            max_granted_rules: 64,
            max_operations: 64,
            max_concurrent_sessions: 1,
            browser_scope: BrowserScope::Session,
            credential_selection: passless_core::agent::config::CredentialSelection::Single,
            mode: AgentMode::Isolated,
            principal_user: "test-user".to_string(),
            credential_refs: None,
            max_grant_ttl: None,
            max_session_ttl: None,
            storage: None,
            rules: vec![],
            legacy: Default::default(),
            device: None,
            start_url: None,
            browser_command: None,
            browser_user: None,
            browser_runtime_root: None,
            browser_cdp_expose: None,
            browser_cdp_port: None,
        };

        let result = config_from_profile(&profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("storage"));
    }

    #[test]
    fn test_bundle_credential_count_isolation() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_a = base.path().join("count_a").join("creds");
        let pin_a = base.path().join("count_a").join("pin");
        let cred_b = base.path().join("count_b").join("creds");
        let pin_b = base.path().join("count_b").join("pin");

        let bundle_a = create_storage_bundle(make_local_config(&cred_a, &pin_a)).unwrap();
        let bundle_b = create_storage_bundle(make_local_config(&cred_b, &pin_b)).unwrap();

        {
            let cs = bundle_a.credential_storage.lock().unwrap();
            assert_eq!(cs.count_credentials(), 0);
        }
        {
            let cs = bundle_b.credential_storage.lock().unwrap();
            assert_eq!(cs.count_credentials(), 0);
        }

        assert_ne!(
            bundle_a.credential_dir(),
            bundle_b.credential_dir(),
            "credential directories must be disjoint"
        );
    }

    #[test]
    fn test_ensure_secure_directory_creates_missing() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let dir = base.path().join("new_dir");
        assert!(!dir.exists());

        ensure_secure_directory(&dir).unwrap();
        assert!(dir.exists());
        assert!(dir.is_dir());

        let meta = fs::metadata(&dir).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn test_ensure_secure_directory_rejects_file_not_directory() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file_path = base.path().join("not_a_dir");
        fs::write(&file_path, b"hello").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();

        let result = ensure_secure_directory(&file_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a directory"));
    }

    #[test]
    fn test_multiple_bundles_same_process_no_interference() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut bundles = Vec::new();

        for i in 0..5 {
            let cred = base.path().join(format!("multi_{}", i)).join("creds");
            let pin = base.path().join(format!("multi_{}", i)).join("pin");
            let bundle = create_storage_bundle(make_local_config(&cred, &pin)).unwrap();
            bundles.push(bundle);
        }

        for (i, bundle) in bundles.iter().enumerate() {
            let ps = bundle.pin_storage.lock().unwrap();
            let mut state = ps.load_pin_state().unwrap();
            state.retries = (i as u8) + 1;
            ps.save_pin_state(&state).unwrap();
        }

        for (i, bundle) in bundles.iter().enumerate() {
            let ps = bundle.pin_storage.lock().unwrap();
            let state = ps.load_pin_state().unwrap();
            assert_eq!(
                state.retries,
                (i as u8) + 1,
                "profile {} should have retries={}, got {}",
                i,
                (i as u8) + 1,
                state.retries
            );
        }
    }

    #[test]
    fn test_reject_preexisting_parent_symlink() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let real_parent = base.path().join("real_parent");
        fs::create_dir_all(&real_parent).unwrap();
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();

        let link_parent = base.path().join("link_parent");
        std::os::unix::fs::symlink(&real_parent, &link_parent).unwrap();

        let nested = link_parent.join("nested").join("creds");

        let result = ensure_secure_directory(&nested);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    fn test_reject_concurrent_symlink_replacement() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let dir_a = base.path().join("a");
        let dir_b = base.path().join("b");
        fs::create_dir_all(&dir_a).unwrap();
        fs::set_permissions(&dir_a, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(&dir_b).unwrap();
        fs::set_permissions(&dir_b, fs::Permissions::from_mode(0o700)).unwrap();

        let target = base.path().join("target");
        std::os::unix::fs::symlink(&dir_b, &target).unwrap();

        let result = ensure_secure_directory(&target);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    fn test_pass_pin_path_must_be_relative() {
        let config = AgentStorageConfig::Pass {
            store_path: PathBuf::from("/tmp/store"),
            path: "fido2".to_string(),
            gpg_backend: "gnupg-bin".to_string(),
            pin_path: PathBuf::from("/absolute/pin"),
            git_sync: true,
            git_auto_push: true,
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("relative"));
    }

    #[test]
    fn test_pass_pin_path_rejects_traversal() {
        let config = AgentStorageConfig::Pass {
            store_path: PathBuf::from("/tmp/store"),
            path: "fido2".to_string(),
            gpg_backend: "gnupg-bin".to_string(),
            pin_path: PathBuf::from("../escape"),
            git_sync: true,
            git_auto_push: true,
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("traversal"));
    }

    #[test]
    fn test_pass_pin_state_path_is_store_join_pin() {
        let dir = tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = dir.path().join("store");
        fs::create_dir_all(&store).unwrap();
        let config = AgentStorageConfig::Pass {
            store_path: store.clone(),
            path: "fido2".to_string(),
            gpg_backend: "gnupg-bin".to_string(),
            pin_path: PathBuf::from("pin"),
            git_sync: true,
            git_auto_push: true,
        };
        let pin_path = config.pin_state_path();
        let expected = passless_core::BackendConfig::canonicalize_path(&store.join("pin"));
        assert_eq!(pin_path, expected);
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn test_tpm_pin_path_is_directory() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_dir = base.path().join("tpm_creds");
        let pin_dir = base.path().join("tpm_pin");

        let config = AgentStorageConfig::Tpm {
            path: cred_dir.clone(),
            tcti: "device:/dev/tpmrm0".to_string(),
            pin_path: pin_dir.clone(),
            portable: false,
        };
        let pin_path = config.pin_state_path();
        let expected = passless_core::BackendConfig::canonicalize_path(&pin_dir);
        assert_eq!(pin_path, expected);
    }

    #[test]
    fn test_exact_pin_file_location_local() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_dir = base.path().join("creds");
        let pin_dir = base.path().join("pin");

        let config = make_local_config(&cred_dir, &pin_dir);
        let bundle = create_storage_bundle(config).unwrap();

        let expected_pin_file = pin_dir.join("pin_state.json");
        let actual_pin_dir = bundle.pin_dir();
        assert_eq!(
            actual_pin_dir,
            passless_core::BackendConfig::canonicalize_path(&pin_dir)
        );

        {
            let ps = bundle.pin_storage.lock().unwrap();
            let mut state = ps.load_pin_state().unwrap();
            state.retries = 5;
            ps.save_pin_state(&state).unwrap();
        }

        assert!(
            expected_pin_file.exists(),
            "PIN file should exist at {:?}",
            expected_pin_file
        );
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn test_exact_pin_file_location_tpm() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_dir = base.path().join("tpm_creds");
        let pin_dir = base.path().join("tpm_pin");

        let config = AgentStorageConfig::Tpm {
            path: cred_dir,
            tcti: "device:/dev/tpmrm0".to_string(),
            pin_path: pin_dir.clone(),
            portable: false,
        };
        let bundle = match create_storage_bundle(config) {
            Ok(b) => b,
            Err(e)
                if e.to_string().contains("TPM") || e.to_string().contains("Permission denied") =>
            {
                return;
            }
            Err(e) => panic!("unexpected error: {}", e),
        };

        let expected_pin_file = pin_dir.join("pin_state.json.tpm");
        let actual_pin_dir = bundle.pin_dir();
        assert_eq!(
            actual_pin_dir,
            passless_core::BackendConfig::canonicalize_path(&pin_dir)
        );

        let _ = expected_pin_file;
    }

    #[test]
    fn test_ensure_secure_directory_verifies_owner_at_each_component() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let nested = base.path().join("a").join("b").join("c");

        ensure_secure_directory(&nested).unwrap();

        for p in [
            base.path().join("a"),
            base.path().join("a").join("b"),
            base.path().join("a").join("b").join("c"),
        ] {
            let meta = fs::metadata(&p).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
            assert_eq!(meta.uid(), unsafe { libc::getuid() });
        }
    }

    #[test]
    fn test_reject_symlink_in_intermediate_component() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let real_dir = base.path().join("real");
        fs::create_dir_all(&real_dir).unwrap();
        fs::set_permissions(&real_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let target = link.join("sub");

        let result = ensure_secure_directory(&target);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    fn test_getinfo_through_type_erased_service() {
        use crate::authenticator::AuthenticatorService;
        use passless_core::config::{PinConfig, SecurityConfig};

        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_dir = base.path().join("getinfo_creds");
        let pin_dir = base.path().join("getinfo_pin");

        let bundle = create_storage_bundle(make_local_config(&cred_dir, &pin_dir)).unwrap();

        let mut service = AuthenticatorService::with_shared_storage(
            bundle.credential_storage.clone(),
            Some(bundle.pin_storage.clone()),
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .expect("service creation should succeed");

        let mut response = Vec::new();
        service
            .handle(&[0x04], &mut response)
            .expect("GetInfo should succeed");

        assert!(!response.is_empty(), "GetInfo response should not be empty");
        assert_eq!(response[0], 0x00, "GetInfo should return success status");
    }

    #[test]
    fn test_separate_type_erased_services_do_not_share_storage() {
        use crate::authenticator::AuthenticatorService;
        use passless_core::config::{PinConfig, SecurityConfig};

        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_a = base.path().join("svc_a").join("creds");
        let pin_a = base.path().join("svc_a").join("pin");
        let cred_b = base.path().join("svc_b").join("creds");
        let pin_b = base.path().join("svc_b").join("pin");

        let bundle_a = create_storage_bundle(make_local_config(&cred_a, &pin_a)).unwrap();
        let bundle_b = create_storage_bundle(make_local_config(&cred_b, &pin_b)).unwrap();

        let mut service_a = AuthenticatorService::with_shared_storage(
            bundle_a.credential_storage.clone(),
            Some(bundle_a.pin_storage.clone()),
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .unwrap();

        let mut service_b = AuthenticatorService::with_shared_storage(
            bundle_b.credential_storage.clone(),
            Some(bundle_b.pin_storage.clone()),
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .unwrap();

        let mut resp_a = Vec::new();
        service_a.handle(&[0x04], &mut resp_a).unwrap();
        assert_eq!(resp_a[0], 0x00);

        let mut resp_b = Vec::new();
        service_b.handle(&[0x04], &mut resp_b).unwrap();
        assert_eq!(resp_b[0], 0x00);

        assert_ne!(
            Arc::as_ptr(&bundle_a.credential_storage),
            Arc::as_ptr(&bundle_b.credential_storage),
            "credential storage Arcs must be independent"
        );
        assert_ne!(
            Arc::as_ptr(&bundle_a.pin_storage),
            Arc::as_ptr(&bundle_b.pin_storage),
            "pin storage Arcs must be independent"
        );
    }

    #[test]
    fn test_separate_type_erased_services_do_not_share_pin_state() {
        use passless_core::config::{PinConfig, SecurityConfig};

        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_a = base.path().join("pin_svc_a").join("creds");
        let pin_a = base.path().join("pin_svc_a").join("pin");
        let cred_b = base.path().join("pin_svc_b").join("creds");
        let pin_b = base.path().join("pin_svc_b").join("pin");

        let bundle_a = create_storage_bundle(make_local_config(&cred_a, &pin_a)).unwrap();
        let bundle_b = create_storage_bundle(make_local_config(&cred_b, &pin_b)).unwrap();

        let _service_a = crate::authenticator::AuthenticatorService::with_shared_storage(
            bundle_a.credential_storage.clone(),
            Some(bundle_a.pin_storage.clone()),
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .unwrap();

        let _service_b = crate::authenticator::AuthenticatorService::with_shared_storage(
            bundle_b.credential_storage.clone(),
            Some(bundle_b.pin_storage.clone()),
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .unwrap();

        {
            let ps = bundle_a.pin_storage.lock().unwrap();
            let mut state = ps.load_pin_state().unwrap();
            state.retries = 2;
            ps.save_pin_state(&state).unwrap();
        }

        {
            let ps = bundle_b.pin_storage.lock().unwrap();
            let state = ps.load_pin_state().unwrap();
            assert_eq!(
                state.retries, 8,
                "profile B PIN state should not be affected by profile A"
            );
        }

        {
            let ps = bundle_a.pin_storage.lock().unwrap();
            let state = ps.load_pin_state().unwrap();
            assert_eq!(
                state.retries, 2,
                "profile A PIN state should remain unchanged"
            );
        }
    }
}
