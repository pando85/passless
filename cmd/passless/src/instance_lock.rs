use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use passless_core::BackendConfig;
use sha2::{Digest, Sha256};

#[derive(Debug)]
#[must_use = "InstanceLock releases the lock when dropped; bind it to a variable to hold the lock"]
pub struct InstanceLock {
    _flock: Flock<File>,
    lock_path: PathBuf,
}

impl InstanceLock {
    pub fn acquire(backend: &BackendConfig) -> passless_core::Result<Self> {
        Self::acquire_with_runtime_dir(backend, None)
    }

    fn acquire_with_runtime_dir(
        backend: &BackendConfig,
        runtime_dir_override: Option<&Path>,
    ) -> passless_core::Result<Self> {
        let runtime_dir = if let Some(dir) = runtime_dir_override {
            dir.to_path_buf()
        } else {
            Self::resolve_runtime_dir()?
        };
        let lock_dir = runtime_dir.join("passless");
        Self::ensure_secure_dir(&lock_dir)?;

        let lock_file = Self::lock_filename(backend);
        let lock_path = lock_dir.join(&lock_file);

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| {
                passless_core::Error::Other(format!(
                    "Failed to open lock file {}: {}",
                    lock_path.display(),
                    e
                ))
            })?;

        let metadata = fs::metadata(&lock_path).map_err(|e| {
            passless_core::Error::Other(format!(
                "Failed to stat lock file {}: {}",
                lock_path.display(),
                e
            ))
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                passless_core::Error::Other(format!(
                    "Failed to set lock file permissions {}: {}",
                    lock_path.display(),
                    e
                ))
            })?;
        }

        let flock =
            Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| match e {
                nix::errno::Errno::EWOULDBLOCK => passless_core::Error::AlreadyRunning {
                    path: backend.state_path(),
                },
                _ => passless_core::Error::Other(format!("Failed to acquire instance lock: {}", e)),
            })?;

        Self::write_metadata(&flock, backend);

        Ok(Self {
            _flock: flock,
            lock_path,
        })
    }

    fn resolve_runtime_dir() -> passless_core::Result<PathBuf> {
        if let Some(dir) = dirs::runtime_dir() {
            return Ok(dir);
        }
        let uid = unsafe { libc::getuid() };
        let fallback = PathBuf::from(format!("/tmp/passless-{}", uid));
        Self::ensure_secure_dir(&fallback)?;
        Ok(fallback)
    }

    fn ensure_secure_dir(path: &Path) -> passless_core::Result<()> {
        if !path.exists() {
            fs::create_dir_all(path).map_err(|e| {
                passless_core::Error::Other(format!(
                    "Failed to create runtime directory {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        let metadata = fs::metadata(path).map_err(|e| {
            passless_core::Error::Other(format!(
                "Failed to stat runtime directory {}: {}",
                path.display(),
                e
            ))
        })?;

        if !metadata.is_dir() {
            return Err(passless_core::Error::Other(format!(
                "Runtime path is not a directory: {}",
                path.display()
            )));
        }

        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o700 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| {
                passless_core::Error::Other(format!(
                    "Failed to set permissions on runtime directory {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let expected_uid = unsafe { libc::getuid() };
            if metadata.uid() != expected_uid {
                return Err(passless_core::Error::Other(format!(
                    "Runtime directory {} is not owned by current user (uid {})",
                    path.display(),
                    expected_uid
                )));
            }
        }

        Ok(())
    }

    fn lock_filename(backend: &BackendConfig) -> String {
        let state_path = backend.state_path();
        let mut hasher = Sha256::new();
        hasher.update(state_path.as_os_str().as_encoded_bytes());
        let hash = hasher.finalize();
        format!("{}.lock", hex::encode(&hash[..16]))
    }

    fn write_metadata(flock: &Flock<File>, backend: &BackendConfig) {
        let mut file: &File = flock;
        let metadata = format!(
            "pid={}\nbackend={}\nstate={}\n",
            std::process::id(),
            match backend {
                BackendConfig::Local { .. } => "local",
                BackendConfig::Pass { .. } => "pass",
                #[cfg(feature = "tpm")]
                BackendConfig::Tpm { .. } => "tpm",
            },
            backend.state_path().display()
        );
        let _ = file.set_len(0);
        let _ = file.write_all(metadata.as_bytes());
        let _ = file.sync_all();
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn test_backend(path: &str) -> BackendConfig {
        BackendConfig::Local {
            path: path.to_string(),
        }
    }

    #[test]
    fn test_lock_filename_is_hash() {
        let backend = test_backend("/home/user/.password-store/fido2");
        let filename = InstanceLock::lock_filename(&backend);
        assert!(filename.ends_with(".lock"));
        assert!(!filename.contains("password-store"));
        assert!(!filename.contains("fido2"));
    }

    #[test]
    fn test_lock_filename_same_for_same_identity() {
        let a = test_backend("/tmp/passless_test");
        let b = test_backend("/tmp/passless_test");
        assert_eq!(
            InstanceLock::lock_filename(&a),
            InstanceLock::lock_filename(&b)
        );
    }

    #[test]
    fn test_lock_filename_differs_for_different_identities() {
        let a = test_backend("/tmp/passless_a");
        let b = test_backend("/tmp/passless_b");
        assert_ne!(
            InstanceLock::lock_filename(&a),
            InstanceLock::lock_filename(&b)
        );
    }

    #[test]
    fn test_acquire_and_drop() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_dir = dir.path().to_path_buf();

        let backend = test_backend(&dir.path().join("state_a").display().to_string());

        let lock = InstanceLock::acquire_with_runtime_dir(&backend, Some(&runtime_dir))
            .expect("first lock should succeed");
        let lock_path = lock.lock_path().to_path_buf();
        assert!(lock_path.exists());

        let metadata = fs::metadata(&lock_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        drop(lock);

        let lock2 = InstanceLock::acquire_with_runtime_dir(&backend, Some(&runtime_dir))
            .expect("should reacquire after drop");
        drop(lock2);
    }

    #[test]
    fn test_concurrent_lock_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_dir = dir.path().join("runtime");
        fs::create_dir_all(&runtime_dir).unwrap();

        let state_dir = dir.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let backend = test_backend(&state_dir.display().to_string());

        let _lock1 = InstanceLock::acquire_with_runtime_dir(&backend, Some(&runtime_dir))
            .expect("first lock should succeed");

        let result = InstanceLock::acquire_with_runtime_dir(&backend, Some(&runtime_dir));
        assert!(result.is_err());
        match result.unwrap_err() {
            passless_core::Error::AlreadyRunning { path } => {
                assert_eq!(path, backend.state_path());
            }
            other => panic!("Expected AlreadyRunning, got: {:?}", other),
        }
    }

    #[test]
    fn test_concurrent_lock_different_identities() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_dir = dir.path().join("runtime");
        fs::create_dir_all(&runtime_dir).unwrap();

        let state_a = dir.path().join("state_a");
        let state_b = dir.path().join("state_b");
        fs::create_dir_all(&state_a).unwrap();
        fs::create_dir_all(&state_b).unwrap();

        let backend_a = test_backend(&state_a.display().to_string());
        let backend_b = test_backend(&state_b.display().to_string());

        let _lock_a = InstanceLock::acquire_with_runtime_dir(&backend_a, Some(&runtime_dir))
            .expect("lock A should succeed");
        let _lock_b = InstanceLock::acquire_with_runtime_dir(&backend_b, Some(&runtime_dir))
            .expect("lock B should succeed");
    }

    #[test]
    fn test_runtime_dir_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_dir = dir.path().join("runtime");
        fs::create_dir_all(&runtime_dir).unwrap();

        let backend = test_backend(&dir.path().join("state").display().to_string());

        let _lock = InstanceLock::acquire_with_runtime_dir(&backend, Some(&runtime_dir))
            .expect("lock should succeed");

        let passless_dir = runtime_dir.join("passless");
        let metadata = fs::metadata(&passless_dir).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn test_stale_lock_file_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_dir = dir.path().join("runtime");
        fs::create_dir_all(&runtime_dir).unwrap();

        let state_dir = dir.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let backend = test_backend(&state_dir.display().to_string());

        let lock = InstanceLock::acquire_with_runtime_dir(&backend, Some(&runtime_dir))
            .expect("first lock should succeed");
        let lock_path = lock.lock_path().to_path_buf();
        drop(lock);

        assert!(lock_path.exists());

        let lock2 = InstanceLock::acquire_with_runtime_dir(&backend, Some(&runtime_dir))
            .expect("should acquire despite stale file");
        drop(lock2);
    }
}
