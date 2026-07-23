use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use passless_core::agent::CredentialRef;
use passless_core::agent::config::AgentStorageConfig;
use passless_core::error::{Error, Result};

#[cfg(test)]
use passless_core::agent::config::AgentProfileConfig;

use crate::pin_storage::PinStorage;
use crate::storage::CredentialStorage;
use crate::storage::pass::GpgBackend;

use super::storage::{CeremonyScope, SharedDelegatedStorage};

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
        } => {
            let gpg = gpg_backend.parse::<GpgBackend>().map_err(|e| {
                Error::Storage(format!("invalid GPG backend '{}': {}", gpg_backend, e))
            })?;

            let cred_storage = crate::storage::PassStorageAdapter::new_with_options(
                store_path.clone(),
                PathBuf::from(path),
                gpg,
                allow_create_without_prompt,
            )
            .map_err(|e| {
                Error::Storage(format!(
                    "failed to create pass credential storage at {}/{}: {}",
                    store_path.display(),
                    path,
                    e
                ))
            })?;

            let pin_storage =
                crate::pin_storage::PassPinStorage::new(store_path.clone(), pin_path.clone(), gpg);

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

pub fn create_shared_delegated_storage<S: CredentialStorage + 'static>(
    human: Arc<Mutex<S>>,
    rp_ids: Vec<String>,
    credential_refs: Vec<CredentialRef>,
    constant_counter: bool,
) -> Result<(SharedDelegatedStorage<S>, CeremonyScope)> {
    create_shared_delegated_storage_with_registration(
        human,
        rp_ids,
        credential_refs,
        constant_counter,
        false,
    )
}

pub fn create_shared_delegated_storage_with_registration<S: CredentialStorage + 'static>(
    human: Arc<Mutex<S>>,
    rp_ids: Vec<String>,
    credential_refs: Vec<CredentialRef>,
    constant_counter: bool,
    registration_allowed: bool,
) -> Result<(SharedDelegatedStorage<S>, CeremonyScope)> {
    let mut delegated = SharedDelegatedStorage::new(human, rp_ids, credential_refs)
        .with_constant_counter_mode(constant_counter)
        .with_registration_allowed(registration_allowed);
    delegated
        .build_index()
        .map_err(|e| Error::Storage(format!("failed to build delegated index: {}", e)))?;
    let scope = delegated.scope();
    Ok((delegated, scope))
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
        use passless_core::agent::{AgentMode, DeviceIdentity};

        let profile = AgentProfileConfig {
            mode: AgentMode::Isolated,
            principal_user: "test-user".to_string(),
            rp_ids: vec!["example.com".to_string()],
            require_uv: true,
            credential_refs: None,
            max_grant_ttl: None,
            max_session_ttl: None,
            storage: Some(AgentStorageConfig::Local {
                path: PathBuf::from("/tmp/test/creds"),
                pin_path: PathBuf::from("/tmp/test/pin"),
            }),
            registration_allowed: false,
            rules: vec![],
            delegated_registration_storage: None,
            device: DeviceIdentity {
                name: "test".to_string(),
                phys: "test".to_string(),
                uniq: "test".to_string(),
                vendor_id: 1,
                product_id: 1,
            },
            start_url: None,
            browser_command: None,
            browser_user: None,
            browser_runtime_root: None,
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
        use passless_core::agent::{AgentMode, DeviceIdentity};

        let profile = AgentProfileConfig {
            mode: AgentMode::Isolated,
            principal_user: "test-user".to_string(),
            rp_ids: vec!["example.com".to_string()],
            require_uv: true,
            credential_refs: None,
            max_grant_ttl: None,
            max_session_ttl: None,
            storage: None,
            registration_allowed: false,
            rules: vec![],
            delegated_registration_storage: None,
            device: DeviceIdentity {
                name: "test".to_string(),
                phys: "test".to_string(),
                uniq: "test".to_string(),
                vendor_id: 1,
                product_id: 1,
            },
            start_url: None,
            browser_command: None,
            browser_user: None,
            browser_runtime_root: None,
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

    fn make_test_credential(
        id: &[u8],
        rp_id: &str,
        user_id: &[u8],
        sign_count: u32,
    ) -> soft_fido2::Credential {
        use soft_fido2_ctap::SecBytes;
        soft_fido2::Credential {
            id: id.to_vec(),
            rp: soft_fido2_ctap::types::RelyingParty {
                id: rp_id.to_string(),
                name: Some("Test".to_string()),
            },
            user: soft_fido2_ctap::types::User {
                id: user_id.to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
            },
            sign_count,
            alg: -7,
            key: soft_fido2_ctap::CredentialKey::software(SecBytes::new(vec![0xAA; 32])),
            created: 1000,
            discoverable: true,
            extensions: soft_fido2::Extensions::default(),
        }
    }

    #[test]
    fn test_shared_delegated_view_sees_human_credential_only_under_active_scope() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_dir = base.path().join("del_creds");

        let human_storage = crate::storage::LocalStorageAdapter::new(cred_dir).unwrap();
        let human: Arc<Mutex<Box<dyn CredentialStorage>>> =
            Arc::new(Mutex::new(Box::new(human_storage)));

        {
            let mut h = human.lock().unwrap();
            let cred = make_test_credential(b"cred1", "example.com", b"user1", 0);
            let cred_ref = soft_fido2::CredentialRef {
                id: &cred.id,
                rp_id: &cred.rp.id,
                rp_name: cred.rp.name.as_deref(),
                user_id: &cred.user.id,
                user_name: cred.user.name.as_deref(),
                user_display_name: cred.user.display_name.as_deref(),
                sign_count: &cred.sign_count,
                alg: &cred.alg,
                key: &cred.key,
                created: &cred.created,
                discoverable: &cred.discoverable,
                cred_protect: cred.extensions.cred_protect.as_ref(),
                cred_random: None,
            };
            h.write(cred_ref).unwrap();
            assert_eq!(h.count_credentials(), 1);
        }

        let cred_ref_obj = passless_core::agent::CredentialRef::with_default_domain(b"cred1");

        let (mut delegated, scope) = create_shared_delegated_storage(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_obj],
            false,
        )
        .unwrap();

        assert_eq!(delegated.count_credentials(), 0);

        let result_no_ceremony =
            delegated.read_first(crate::storage::CredentialFilter::ByRp("example.com".into()));
        assert!(result_no_ceremony.is_err());

        let _guard = scope
            .activate_authenticate_for_rp(
                passless_core::agent::CredentialRef::with_default_domain(b"cred1"),
                "example.com",
            )
            .unwrap();

        let result_with_ceremony =
            delegated.read_first(crate::storage::CredentialFilter::ByRp("example.com".into()));
        assert!(result_with_ceremony.is_ok());
        assert_eq!(result_with_ceremony.unwrap().id, b"cred1");

        drop(_guard);
        assert_eq!(scope.active_cred_ref(), None);

        let result_after_drop =
            delegated.read_first(crate::storage::CredentialFilter::ByRp("example.com".into()));
        assert!(result_after_drop.is_err());
    }

    #[test]
    fn test_shared_delegated_write_monotonic_counter_only() {
        let base = tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cred_dir = base.path().join("mono_creds");

        let human_storage = crate::storage::LocalStorageAdapter::new(cred_dir).unwrap();
        let human: Arc<Mutex<Box<dyn CredentialStorage>>> =
            Arc::new(Mutex::new(Box::new(human_storage)));

        let cred = make_test_credential(b"cred1", "example.com", b"user1", 5);
        {
            let mut h = human.lock().unwrap();
            let cred_ref = soft_fido2::CredentialRef {
                id: &cred.id,
                rp_id: &cred.rp.id,
                rp_name: cred.rp.name.as_deref(),
                user_id: &cred.user.id,
                user_name: cred.user.name.as_deref(),
                user_display_name: cred.user.display_name.as_deref(),
                sign_count: &cred.sign_count,
                alg: &cred.alg,
                key: &cred.key,
                created: &cred.created,
                discoverable: &cred.discoverable,
                cred_protect: cred.extensions.cred_protect.as_ref(),
                cred_random: None,
            };
            h.write(cred_ref).unwrap();
        }

        let cred_ref_obj = passless_core::agent::CredentialRef::with_default_domain(b"cred1");

        let (mut delegated, scope) = create_shared_delegated_storage(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_obj],
            false,
        )
        .unwrap();

        let _guard = scope
            .activate_authenticate_for_rp(
                passless_core::agent::CredentialRef::with_default_domain(b"cred1"),
                "example.com",
            )
            .unwrap();

        let _ = delegated.read(b"cred1").unwrap();

        let mut regressed = cred.clone();
        regressed.sign_count = 3;
        let regressed_ref = soft_fido2::CredentialRef {
            id: &regressed.id,
            rp_id: &regressed.rp.id,
            rp_name: regressed.rp.name.as_deref(),
            user_id: &regressed.user.id,
            user_name: regressed.user.name.as_deref(),
            user_display_name: regressed.user.display_name.as_deref(),
            sign_count: &regressed.sign_count,
            alg: &regressed.alg,
            key: &regressed.key,
            created: &regressed.created,
            discoverable: &regressed.discoverable,
            cred_protect: regressed.extensions.cred_protect.as_ref(),
            cred_random: None,
        };
        let result = delegated.write(regressed_ref);
        assert!(result.is_err());

        let mut same = cred.clone();
        same.sign_count = 5;
        let same_ref = soft_fido2::CredentialRef {
            id: &same.id,
            rp_id: &same.rp.id,
            rp_name: same.rp.name.as_deref(),
            user_id: &same.user.id,
            user_name: same.user.name.as_deref(),
            user_display_name: same.user.display_name.as_deref(),
            sign_count: &same.sign_count,
            alg: &same.alg,
            key: &same.key,
            created: &same.created,
            discoverable: &same.discoverable,
            cred_protect: same.extensions.cred_protect.as_ref(),
            cred_random: None,
        };
        let result = delegated.write(same_ref);
        assert!(result.is_err());

        let mut advanced = cred.clone();
        advanced.sign_count = 6;
        let advanced_ref = soft_fido2::CredentialRef {
            id: &advanced.id,
            rp_id: &advanced.rp.id,
            rp_name: advanced.rp.name.as_deref(),
            user_id: &advanced.user.id,
            user_name: advanced.user.name.as_deref(),
            user_display_name: advanced.user.display_name.as_deref(),
            sign_count: &advanced.sign_count,
            alg: &advanced.alg,
            key: &advanced.key,
            created: &advanced.created,
            discoverable: &advanced.discoverable,
            cred_protect: advanced.extensions.cred_protect.as_ref(),
            cred_random: None,
        };
        let result = delegated.write(advanced_ref);
        assert!(result.is_ok());
    }

    mod composition_conformance {
        use super::*;
        use crate::storage::CredentialFilter;
        use std::collections::VecDeque;

        fn secure_temp_dir() -> tempfile::TempDir {
            let dir = tempdir().unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            dir
        }

        fn comp_test_credential(
            id: &[u8],
            rp_id: &str,
            user_id: &[u8],
            sign_count: u32,
        ) -> soft_fido2::Credential {
            make_test_credential(id, rp_id, user_id, sign_count)
        }

        fn comp_cred_to_ref(cred: &soft_fido2::Credential) -> soft_fido2::CredentialRef<'_> {
            soft_fido2::CredentialRef {
                id: &cred.id,
                rp_id: &cred.rp.id,
                rp_name: cred.rp.name.as_deref(),
                user_id: &cred.user.id,
                user_name: cred.user.name.as_deref(),
                user_display_name: cred.user.display_name.as_deref(),
                sign_count: &cred.sign_count,
                alg: &cred.alg,
                key: &cred.key,
                created: &cred.created,
                discoverable: &cred.discoverable,
                cred_protect: cred.extensions.cred_protect.as_ref(),
                cred_random: None,
            }
        }

        fn comp_cred_ref_for(id: &[u8]) -> CredentialRef {
            CredentialRef::with_default_domain(id)
        }

        fn comp_write_seed(
            human: &Arc<Mutex<Box<dyn CredentialStorage>>>,
            cred: &soft_fido2::Credential,
        ) {
            let mut h = human.lock().unwrap();
            let cr = comp_cred_to_ref(cred);
            h.write(cr).unwrap();
        }

        fn run_composition_conformance(
            human: Arc<Mutex<Box<dyn CredentialStorage>>>,
            rp_id: &str,
            cred_id: &[u8],
            initial_counter: u32,
        ) {
            let seed = comp_test_credential(cred_id, rp_id, b"user1", initial_counter);
            comp_write_seed(&human, &seed);

            {
                let h = human.lock().unwrap();
                assert_eq!(h.count_credentials(), 1);
            }

            let agent_cred_ref = comp_cred_ref_for(cred_id);
            let (mut delegated, scope) = create_shared_delegated_storage(
                human.clone(),
                vec![rp_id.to_string()],
                vec![agent_cred_ref.clone()],
                false,
            )
            .unwrap();

            assert_eq!(delegated.count_credentials(), 0);

            let no_ceremony = delegated.read_first(CredentialFilter::ByRp(rp_id.into()));
            assert!(no_ceremony.is_err());

            let guard = scope
                .activate_authenticate_for_rp(agent_cred_ref.clone(), rp_id)
                .unwrap();

            let found = delegated
                .read_first(CredentialFilter::ByRp(rp_id.into()))
                .unwrap();
            assert_eq!(found.id, cred_id);
            assert_eq!(found.rp.id, rp_id);
            assert_eq!(found.sign_count, initial_counter);

            assert!(
                delegated
                    .read_first(CredentialFilter::ByRp("evil.com".into()))
                    .is_err()
            );

            let direct = delegated.read(cred_id).unwrap();
            assert_eq!(direct.id, cred_id);

            let mut advanced = seed.clone();
            advanced.sign_count = initial_counter + 1;
            let adv_ref = comp_cred_to_ref(&advanced);
            delegated.write(adv_ref).unwrap();

            let after_write = delegated.read(cred_id).unwrap();
            assert_eq!(after_write.sign_count, initial_counter + 1);

            drop(guard);

            assert!(delegated.read(cred_id).is_err());
            assert_eq!(delegated.count_credentials(), 0);

            let mut h = human.lock().unwrap();
            let persisted = h.read(cred_id).unwrap();
            assert_eq!(persisted.sign_count, initial_counter + 1);
            assert_eq!(h.count_credentials(), 1);

            h.cleanup_expired_cache();
        }

        fn run_cleanup_propagation(human: Arc<Mutex<Box<dyn CredentialStorage>>>) {
            let (mut delegated, _scope) =
                create_shared_delegated_storage(human.clone(), vec![], vec![], false).unwrap();
            delegated.cleanup_expired_cache();
        }

        fn run_no_second_adapter_check(human: &Arc<Mutex<Box<dyn CredentialStorage>>>) {
            let seed = comp_test_credential(b"cred1", "example.com", b"user1", 0);
            comp_write_seed(human, &seed);
            let agent_cred_ref = comp_cred_ref_for(b"cred1");

            let (mut delegated_a, scope_a) = create_shared_delegated_storage(
                human.clone(),
                vec!["example.com".to_string()],
                vec![agent_cred_ref.clone()],
                false,
            )
            .unwrap();

            let (mut delegated_b, scope_b) = create_shared_delegated_storage(
                human.clone(),
                vec!["example.com".to_string()],
                vec![agent_cred_ref.clone()],
                false,
            )
            .unwrap();

            let _guard_a = scope_a
                .activate_authenticate_for_rp(agent_cred_ref.clone(), "example.com")
                .unwrap();
            let _guard_b = scope_b
                .activate_authenticate_for_rp(agent_cred_ref, "example.com")
                .unwrap();

            let mut advanced = seed.clone();
            advanced.sign_count = 1;
            delegated_a.write(comp_cred_to_ref(&advanced)).unwrap();
            assert_eq!(delegated_b.read(b"cred1").unwrap().sign_count, 1);

            advanced.sign_count = 2;
            delegated_b.write(comp_cred_to_ref(&advanced)).unwrap();
            assert_eq!(delegated_a.read(b"cred1").unwrap().sign_count, 2);
        }

        struct ProcessEnvGuard {
            key: &'static str,
            previous: Option<std::ffi::OsString>,
        }

        impl ProcessEnvGuard {
            unsafe fn set(key: &'static str, value: &Path) -> Self {
                let previous = std::env::var_os(key);
                unsafe { std::env::set_var(key, value) };
                Self { key, previous }
            }
        }

        impl Drop for ProcessEnvGuard {
            fn drop(&mut self) {
                unsafe {
                    if let Some(value) = &self.previous {
                        std::env::set_var(self.key, value);
                    } else {
                        std::env::remove_var(self.key);
                    }
                }
            }
        }

        fn binary_available(name: &str) -> bool {
            std::process::Command::new("which")
                .arg(name)
                .output()
                .is_ok_and(|o| o.status.success())
        }

        #[test]
        fn local_composition_full_flow() {
            let base = secure_temp_dir();
            let cred_dir = base.path().join("local_comp_creds");
            let pin_dir = base.path().join("local_comp_pin");

            let config = AgentStorageConfig::Local {
                path: cred_dir,
                pin_path: pin_dir,
            };
            let bundle = create_storage_bundle(config).unwrap();

            run_composition_conformance(
                bundle.credential_storage.clone(),
                "example.com",
                b"local-cred-01",
                0,
            );
        }

        #[test]
        fn local_cleanup_propagation() {
            let base = secure_temp_dir();
            let cred_dir = base.path().join("local_cleanup_creds");
            let pin_dir = base.path().join("local_cleanup_pin");

            let config = AgentStorageConfig::Local {
                path: cred_dir,
                pin_path: pin_dir,
            };
            let bundle = create_storage_bundle(config).unwrap();

            run_cleanup_propagation(bundle.credential_storage.clone());
        }

        #[test]
        fn local_no_second_adapter() {
            let base = secure_temp_dir();
            let cred_dir = base.path().join("local_no2nd_creds");
            let pin_dir = base.path().join("local_no2nd_pin");

            let config = AgentStorageConfig::Local {
                path: cred_dir,
                pin_path: pin_dir,
            };
            let bundle = create_storage_bundle(config).unwrap();

            run_no_second_adapter_check(&bundle.credential_storage);
        }

        #[test]
        fn local_counter_persistence_across_sessions() {
            let base = secure_temp_dir();
            let cred_dir = base.path().join("local_persist_creds");
            let pin_dir = base.path().join("local_persist_pin");

            let config = AgentStorageConfig::Local {
                path: cred_dir,
                pin_path: pin_dir,
            };
            let bundle = create_storage_bundle(config).unwrap();
            let human = bundle.credential_storage.clone();

            let seed = comp_test_credential(b"persist-cred", "example.com", b"user1", 10);
            comp_write_seed(&human, &seed);

            let agent_cred_ref = comp_cred_ref_for(b"persist-cred");

            for expected_counter in 11..15 {
                let (mut delegated, scope) = create_shared_delegated_storage(
                    human.clone(),
                    vec!["example.com".to_string()],
                    vec![agent_cred_ref.clone()],
                    false,
                )
                .unwrap();

                let _guard = scope
                    .activate_authenticate_for_rp(agent_cred_ref.clone(), "example.com")
                    .unwrap();

                let cred = delegated.read(b"persist-cred").unwrap();
                assert_eq!(cred.sign_count, expected_counter - 1);

                let mut advanced = seed.clone();
                advanced.sign_count = expected_counter;
                delegated.write(comp_cred_to_ref(&advanced)).unwrap();
            }

            let mut h = human.lock().unwrap();
            let final_cred = h.read(b"persist-cred").unwrap();
            assert_eq!(final_cred.sign_count, 14);
        }

        #[test]
        fn local_concurrent_delegated_sessions_same_human() {
            let base = secure_temp_dir();
            let cred_dir = base.path().join("local_conc_creds");
            let pin_dir = base.path().join("local_conc_pin");

            let config = AgentStorageConfig::Local {
                path: cred_dir,
                pin_path: pin_dir,
            };
            let bundle = create_storage_bundle(config).unwrap();
            let human = bundle.credential_storage.clone();

            let c1 = comp_test_credential(b"conc-cred-1", "example.com", b"user1", 0);
            let c2 = comp_test_credential(b"conc-cred-2", "example.com", b"user2", 0);
            comp_write_seed(&human, &c1);
            comp_write_seed(&human, &c2);

            let ref1 = comp_cred_ref_for(b"conc-cred-1");
            let ref2 = comp_cred_ref_for(b"conc-cred-2");

            let (mut del1, scope1) = create_shared_delegated_storage(
                human.clone(),
                vec!["example.com".to_string()],
                vec![ref1.clone()],
                false,
            )
            .unwrap();

            let (mut del2, scope2) = create_shared_delegated_storage(
                human.clone(),
                vec!["example.com".to_string()],
                vec![ref2.clone()],
                false,
            )
            .unwrap();

            let g1 = scope1
                .activate_authenticate_for_rp(ref1, "example.com")
                .unwrap();
            let g2 = scope2
                .activate_authenticate_for_rp(ref2, "example.com")
                .unwrap();

            let r1 = del1.read(b"conc-cred-1").unwrap();
            assert_eq!(r1.id, b"conc-cred-1");

            let r2 = del2.read(b"conc-cred-2").unwrap();
            assert_eq!(r2.id, b"conc-cred-2");

            assert!(del1.read(b"conc-cred-2").is_err());
            assert!(del2.read(b"conc-cred-1").is_err());

            drop(g1);
            drop(g2);

            let h = human.lock().unwrap();
            assert_eq!(h.count_credentials(), 2);
        }

        #[derive(Clone)]
        struct DeterministicStorage {
            creds: Arc<Mutex<Vec<soft_fido2::Credential>>>,
            iteration: Arc<Mutex<VecDeque<usize>>>,
            cleanup_calls: Arc<Mutex<usize>>,
        }

        impl DeterministicStorage {
            fn new(creds: Vec<soft_fido2::Credential>) -> Self {
                Self {
                    creds: Arc::new(Mutex::new(creds)),
                    iteration: Arc::new(Mutex::new(VecDeque::new())),
                    cleanup_calls: Arc::new(Mutex::new(0)),
                }
            }
        }

        impl CredentialStorage for DeterministicStorage {
            fn read_first(
                &mut self,
                filter: CredentialFilter,
            ) -> soft_fido2::Result<soft_fido2::Credential> {
                let creds = self.creds.lock().unwrap();
                let mut iter = self.iteration.lock().unwrap();
                iter.clear();

                let matching: Vec<usize> = match &filter {
                    CredentialFilter::None => (0..creds.len()).collect(),
                    CredentialFilter::ByRp(rp) => creds
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| c.rp.id == *rp)
                        .map(|(i, _)| i)
                        .collect(),
                    CredentialFilter::ById(id) => creds
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| c.id == *id)
                        .map(|(i, _)| i)
                        .collect(),
                    CredentialFilter::ByHash(_) => vec![],
                };

                if matching.is_empty() {
                    return Err(soft_fido2::Error::DoesNotExist);
                }

                for &idx in &matching[1..] {
                    iter.push_back(idx);
                }

                Ok(creds[matching[0]].clone())
            }

            fn read_next(&mut self) -> soft_fido2::Result<soft_fido2::Credential> {
                let creds = self.creds.lock().unwrap();
                let mut iter = self.iteration.lock().unwrap();
                match iter.pop_front() {
                    Some(idx) => Ok(creds[idx].clone()),
                    None => Err(soft_fido2::Error::DoesNotExist),
                }
            }

            fn read(&mut self, id: &[u8]) -> soft_fido2::Result<soft_fido2::Credential> {
                let creds = self.creds.lock().unwrap();
                creds
                    .iter()
                    .find(|c| c.id == id)
                    .cloned()
                    .ok_or(soft_fido2::Error::DoesNotExist)
            }

            fn write(&mut self, cred_ref: soft_fido2::CredentialRef) -> soft_fido2::Result<()> {
                let cred = cred_ref.to_owned();
                let mut creds = self.creds.lock().unwrap();
                if let Some(existing) = creds.iter_mut().find(|c| c.id == cred.id) {
                    *existing = cred;
                } else {
                    creds.push(cred);
                }
                Ok(())
            }

            fn delete(&mut self, id: &[u8]) -> soft_fido2::Result<()> {
                let mut creds = self.creds.lock().unwrap();
                creds.retain(|c| c.id != id);
                Ok(())
            }

            fn count_credentials(&self) -> usize {
                self.creds.lock().unwrap().len()
            }

            fn cleanup_expired_cache(&mut self) {
                *self.cleanup_calls.lock().unwrap() += 1;
            }
        }

        #[test]
        fn deterministic_composition_full_flow() {
            let adapter = DeterministicStorage::new(vec![]);
            let human: Arc<Mutex<Box<dyn CredentialStorage>>> =
                Arc::new(Mutex::new(Box::new(adapter)));

            run_composition_conformance(human, "example.com", b"det-cred-01", 5);
        }

        #[test]
        fn deterministic_cleanup_propagation() {
            let adapter = DeterministicStorage::new(vec![]);
            let cleanup_calls = adapter.cleanup_calls.clone();
            let human: Arc<Mutex<Box<dyn CredentialStorage>>> =
                Arc::new(Mutex::new(Box::new(adapter)));

            run_cleanup_propagation(human);

            assert_eq!(*cleanup_calls.lock().unwrap(), 1);
        }

        #[test]
        fn deterministic_no_second_adapter() {
            let adapter = DeterministicStorage::new(vec![]);
            let human: Arc<Mutex<Box<dyn CredentialStorage>>> =
                Arc::new(Mutex::new(Box::new(adapter)));

            run_no_second_adapter_check(&human);
        }

        #[test]
        fn deterministic_counter_persistence_multiple_sessions() {
            let adapter = DeterministicStorage::new(vec![]);
            let human: Arc<Mutex<Box<dyn CredentialStorage>>> =
                Arc::new(Mutex::new(Box::new(adapter)));

            let seed = comp_test_credential(b"det-persist", "example.com", b"user1", 0);
            comp_write_seed(&human, &seed);

            let agent_cred_ref = comp_cred_ref_for(b"det-persist");

            for expected in 1..6 {
                let (mut delegated, scope) = create_shared_delegated_storage(
                    human.clone(),
                    vec!["example.com".to_string()],
                    vec![agent_cred_ref.clone()],
                    false,
                )
                .unwrap();

                let _guard = scope
                    .activate_authenticate_for_rp(agent_cred_ref.clone(), "example.com")
                    .unwrap();

                let mut advanced = seed.clone();
                advanced.sign_count = expected;
                delegated.write(comp_cred_to_ref(&advanced)).unwrap();
            }

            let mut h = human.lock().unwrap();
            let final_cred = h.read(b"det-persist").unwrap();
            assert_eq!(final_cred.sign_count, 5);
        }

        #[test]
        fn deterministic_isolated_rp_view_through_shared_human() {
            let adapter = DeterministicStorage::new(vec![]);
            let human: Arc<Mutex<Box<dyn CredentialStorage>>> =
                Arc::new(Mutex::new(Box::new(adapter)));

            let c1 = comp_test_credential(b"rp-cred-1", "allowed.com", b"user1", 0);
            let c2 = comp_test_credential(b"rp-cred-2", "forbidden.com", b"user2", 0);
            comp_write_seed(&human, &c1);
            comp_write_seed(&human, &c2);

            let agent_cred_ref = comp_cred_ref_for(b"rp-cred-1");
            let (mut delegated, scope) = create_shared_delegated_storage(
                human.clone(),
                vec!["allowed.com".to_string()],
                vec![agent_cred_ref.clone()],
                false,
            )
            .unwrap();

            let _guard = scope
                .activate_authenticate_for_rp(agent_cred_ref, "allowed.com")
                .unwrap();

            let found = delegated
                .read_first(CredentialFilter::ByRp("allowed.com".into()))
                .unwrap();
            assert_eq!(found.id, b"rp-cred-1");

            assert!(
                delegated
                    .read_first(CredentialFilter::ByRp("forbidden.com".into()))
                    .is_err()
            );

            let h = human.lock().unwrap();
            assert_eq!(h.count_credentials(), 2);
        }

        #[test]
        fn human_regression_getinfo_with_agent_compiled() {
            use crate::authenticator::AuthenticatorService;
            use passless_core::config::{PinConfig, SecurityConfig};

            let base = secure_temp_dir();
            let cred_dir = base.path().join("human_reg_creds");
            let pin_dir = base.path().join("human_reg_pin");

            let config = AgentStorageConfig::Local {
                path: cred_dir,
                pin_path: pin_dir,
            };
            let bundle = create_storage_bundle(config).unwrap();

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
                .expect("GetInfo should succeed without agent interaction");

            assert!(!response.is_empty());
            assert_eq!(response[0], 0x00, "GetInfo should return success status");
        }

        #[test]
        fn human_regression_seed_and_readback_without_ceremony() {
            use crate::authenticator::AuthenticatorService;
            use passless_core::config::{PinConfig, SecurityConfig};

            let base = secure_temp_dir();
            let cred_dir = base.path().join("human_ops_creds");
            let pin_dir = base.path().join("human_ops_pin");

            let config = AgentStorageConfig::Local {
                path: cred_dir,
                pin_path: pin_dir,
            };
            let bundle = create_storage_bundle(config).unwrap();
            let human = bundle.credential_storage.clone();

            let seed = comp_test_credential(b"human-cred", "example.com", b"user1", 0);
            {
                let mut h = human.lock().unwrap();
                let cr = comp_cred_to_ref(&seed);
                h.write(cr).unwrap();
                assert_eq!(h.count_credentials(), 1);
            }

            let mut service = AuthenticatorService::with_shared_storage(
                human.clone(),
                Some(bundle.pin_storage.clone()),
                SecurityConfig::default(),
                PinConfig::default(),
            )
            .unwrap();

            let mut response = Vec::new();
            service.handle(&[0x04], &mut response).unwrap();
            assert_eq!(response[0], 0x00);

            {
                let mut h = human.lock().unwrap();
                let cred = h.read(b"human-cred").unwrap();
                assert_eq!(cred.sign_count, 0);
                assert_eq!(cred.rp.id, "example.com");
            }
        }

        #[test]
        #[ignore]
        fn pass_composition_full_flow() {
            assert!(
                binary_available("gpg") && binary_available("pass"),
                "explicit pass composition validation requires gpg and pass"
            );

            let base = secure_temp_dir();
            let gpg_home = base.path().join(".gnupg");
            fs::create_dir_all(&gpg_home).unwrap();
            fs::set_permissions(&gpg_home, fs::Permissions::from_mode(0o700)).unwrap();

            let batch_file = base.path().join("gpg-batch");
            fs::write(
                &batch_file,
                "Key-Type: RSA\nKey-Length: 2048\nName-Real: Passless Comp Test\n\
                 Name-Email: passless-comp@test.local\nExpire-Date: 0\n%no-protection\n%commit\n",
            )
            .unwrap();

            let output = std::process::Command::new("gpg")
                .arg("--homedir")
                .arg(&gpg_home)
                .arg("--batch")
                .arg("--gen-key")
                .arg(&batch_file)
                .output()
                .unwrap();

            assert!(
                output.status.success(),
                "GPG key generation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let store_path = base.path().join("store");
            fs::create_dir_all(&store_path).unwrap();
            fs::set_permissions(&store_path, fs::Permissions::from_mode(0o700)).unwrap();

            let gpg_id_output = std::process::Command::new("gpg")
                .arg("--homedir")
                .arg(&gpg_home)
                .arg("--list-keys")
                .arg("--with-colons")
                .output()
                .unwrap();
            let gpg_id = String::from_utf8_lossy(&gpg_id_output.stdout)
                .lines()
                .find(|l| l.starts_with("fpr:"))
                .and_then(|l| l.split(':').nth(9).map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    panic!(
                        "Failed to extract GPG key fingerprint from:\n{}",
                        String::from_utf8_lossy(&gpg_id_output.stdout)
                    )
                });

            let init_output = std::process::Command::new("pass")
                .arg("init")
                .arg(&gpg_id)
                .env("PASSWORD_STORE_DIR", &store_path)
                .env("GNUPGHOME", &gpg_home)
                .output()
                .unwrap();

            assert!(init_output.status.success(), "pass init failed");

            let config = AgentStorageConfig::Pass {
                store_path: store_path.clone(),
                path: "fido2".to_string(),
                gpg_backend: "gnupg-bin".to_string(),
                pin_path: PathBuf::from("pin"),
            };

            let _gpg_home_guard = unsafe { ProcessEnvGuard::set("GNUPGHOME", &gpg_home) };
            let _store_guard = unsafe { ProcessEnvGuard::set("PASSWORD_STORE_DIR", &store_path) };

            let bundle = create_storage_bundle(config).expect("pass bundle creation failed");

            run_composition_conformance(
                bundle.credential_storage.clone(),
                "example.com",
                b"pass-cred-01",
                0,
            );
        }

        #[cfg(feature = "tpm")]
        mod tpm_composition {
            use super::*;
            use std::process::{Child, Command, Stdio};

            struct SwtpmHandle {
                child: Child,
                _state_dir: tempfile::TempDir,
                server_port: u16,
            }

            impl SwtpmHandle {
                fn start() -> Option<Self> {
                    if !binary_available("swtpm") {
                        return None;
                    }

                    let state_dir = secure_temp_dir();
                    let (server_port, ctrl_port) = reserve_tcp_ports()?;

                    let child = Command::new("swtpm")
                        .arg("socket")
                        .arg("--tpm2")
                        .arg("--tpmstate")
                        .arg(format!("dir={}", state_dir.path().display()))
                        .arg("--server")
                        .arg(format!("type=tcp,port={server_port}"))
                        .arg("--ctrl")
                        .arg(format!("type=tcp,port={ctrl_port}"))
                        .arg("--flags")
                        .arg("not-need-init,startup-clear")
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .ok()?;

                    let start = std::time::Instant::now();
                    while std::net::TcpStream::connect(("127.0.0.1", server_port)).is_err() {
                        if start.elapsed() > std::time::Duration::from_secs(5) {
                            let mut c = child;
                            let _ = c.kill();
                            let _ = c.wait();
                            return None;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }

                    Some(Self {
                        child,
                        _state_dir: state_dir,
                        server_port,
                    })
                }

                fn tcti(&self) -> String {
                    format!("swtpm:host=127.0.0.1,port={}", self.server_port)
                }
            }

            fn reserve_tcp_ports() -> Option<(u16, u16)> {
                for _ in 0..32 {
                    let server = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
                    let server_port = server.local_addr().ok()?.port();
                    let control_port = server_port.checked_add(1)?;
                    if let Ok(control) = std::net::TcpListener::bind(("127.0.0.1", control_port)) {
                        drop(control);
                        drop(server);
                        return Some((server_port, control_port));
                    }
                }
                None
            }

            impl Drop for SwtpmHandle {
                fn drop(&mut self) {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                }
            }

            #[test]
            #[ignore]
            fn tpm_composition_full_flow() {
                let swtpm = SwtpmHandle::start()
                    .expect("explicit TPM composition validation requires a usable swtpm");

                let base = secure_temp_dir();
                let cred_dir = base.path().join("tpm_comp_creds");
                let pin_dir = base.path().join("tpm_comp_pin");

                let config = AgentStorageConfig::Tpm {
                    path: cred_dir,
                    tcti: swtpm.tcti(),
                    pin_path: pin_dir,
                    portable: false,
                };

                let bundle = create_storage_bundle(config).expect("TPM bundle creation failed");

                run_composition_conformance(
                    bundle.credential_storage.clone(),
                    "example.com",
                    b"tpm-cred-01",
                    0,
                );

                drop(swtpm);
            }

            #[test]
            #[ignore]
            fn tpm_profile_isolation() {
                let swtpm = SwtpmHandle::start()
                    .expect("explicit TPM profile validation requires a usable swtpm");

                let base = secure_temp_dir();
                let cred_a = base.path().join("tpm_a").join("creds");
                let pin_a = base.path().join("tpm_a").join("pin");
                let cred_b = base.path().join("tpm_b").join("creds");
                let pin_b = base.path().join("tpm_b").join("pin");

                let config_a = AgentStorageConfig::Tpm {
                    path: cred_a,
                    tcti: swtpm.tcti(),
                    pin_path: pin_a,
                    portable: false,
                };
                let config_b = AgentStorageConfig::Tpm {
                    path: cred_b,
                    tcti: swtpm.tcti(),
                    pin_path: pin_b,
                    portable: false,
                };

                let bundle_a = create_storage_bundle(config_a).expect("TPM bundle A failed");
                let bundle_b = create_storage_bundle(config_b).expect("TPM bundle B failed");

                assert_ne!(bundle_a.credential_dir(), bundle_b.credential_dir());
                assert_ne!(
                    Arc::as_ptr(&bundle_a.credential_storage),
                    Arc::as_ptr(&bundle_b.credential_storage),
                );

                drop(swtpm);
            }

            #[test]
            #[ignore]
            fn tpm_cleanup_propagation() {
                let swtpm = SwtpmHandle::start()
                    .expect("explicit TPM cleanup validation requires a usable swtpm");

                let base = secure_temp_dir();
                let cred_dir = base.path().join("tpm_cleanup_creds");
                let pin_dir = base.path().join("tpm_cleanup_pin");

                let config = AgentStorageConfig::Tpm {
                    path: cred_dir,
                    tcti: swtpm.tcti(),
                    pin_path: pin_dir,
                    portable: false,
                };

                let bundle = create_storage_bundle(config).expect("TPM bundle failed");

                run_cleanup_propagation(bundle.credential_storage.clone());

                drop(swtpm);
            }

            #[test]
            #[ignore]
            fn tpm_portable_missing_parent_errors() {
                let swtpm = SwtpmHandle::start()
                    .expect("explicit TPM portable validation requires a usable swtpm");

                let base = secure_temp_dir();
                let cred_dir = base.path().join("tpm_portable_unprov_creds");
                let pin_dir = base.path().join("tpm_portable_unprov_pin");

                let config = AgentStorageConfig::Tpm {
                    path: cred_dir,
                    tcti: swtpm.tcti(),
                    pin_path: pin_dir,
                    portable: true,
                };

                let err = create_storage_bundle(config)
                    .expect_err("portable bundle without provisioned parent must fail");
                let msg = err.to_string();
                assert!(
                    msg.contains("passless tpm provision"),
                    "error should mention provisioning command, got: {msg}"
                );

                drop(swtpm);
            }

            #[test]
            #[ignore]
            fn tpm_portable_provisioned_bundle_has_key_provider() {
                use crate::storage::tpm::portable::PortableParent;
                use std::os::unix::fs::PermissionsExt;

                let swtpm = SwtpmHandle::start()
                    .expect("explicit TPM portable validation requires a usable swtpm");

                let base = secure_temp_dir();
                let cred_dir = base.path().join("tpm_portable_prov_creds");
                let pin_dir = base.path().join("tpm_portable_prov_pin");

                std::fs::create_dir_all(&cred_dir).expect("create cred dir");
                fs::set_permissions(&cred_dir, fs::Permissions::from_mode(0o700))
                    .expect("set cred dir perms");
                std::fs::create_dir_all(&pin_dir).expect("create pin dir");
                fs::set_permissions(&pin_dir, fs::Permissions::from_mode(0o700))
                    .expect("set pin dir perms");

                let parent = PortableParent::new(cred_dir.clone(), Some(swtpm.tcti()))
                    .expect("create portable parent");
                let seed = [0x42u8; 32];
                parent.provision(&seed).expect("provision portable parent");
                assert!(parent.is_provisioned());

                let config = AgentStorageConfig::Tpm {
                    path: cred_dir,
                    tcti: swtpm.tcti(),
                    pin_path: pin_dir,
                    portable: true,
                };

                let bundle =
                    create_storage_bundle(config).expect("portable bundle creation failed");
                assert!(
                    bundle.tpm_key_provider.is_some(),
                    "portable bundle must carry a TpmCredentialKeyProvider"
                );

                drop(swtpm);
            }
        }
    }
}
