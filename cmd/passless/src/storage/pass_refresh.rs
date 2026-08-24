use crate::storage::index::load_credential_paths;
use crate::storage::pass::sync::PassGitSync;
use crate::storage::pass::{GpgBackend, PassStorageAdapter as InnerPassStorageAdapter};
use crate::storage::{CredentialFilter, CredentialStorage};
use git2::{Oid, Repository};
use log::{debug, warn};
use passless_core::error::Result;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepositoryGeneration {
    head: Option<Oid>,
    credential_tree_stamp: u64,
}

/// Pass storage wrapper that keeps the in-memory credential index coherent with
/// repository changes performed by another process while Passless is running.
///
/// The underlying pass adapter builds its index once during construction and
/// updates it for writes performed through that adapter. External `git pull`,
/// checkout, or direct credential-file changes bypass those update hooks. This
/// wrapper tracks the Git HEAD plus a cheap metadata fingerprint of `fido2/*.gpg`
/// files and recreates the underlying adapter whenever either changes.
/// Recreating the adapter rescans credential paths without decrypting them and
/// clears the decrypted credential cache, preventing stale file contents from
/// surviving an external update.
pub struct PassStorageAdapter {
    inner: InnerPassStorageAdapter,
    store_path: PathBuf,
    path: PathBuf,
    gpg_backend: GpgBackend,
    allow_create_without_prompt: bool,
    indexed_generation: RepositoryGeneration,
    sync: PassGitSync,
}

impl PassStorageAdapter {
    #[allow(dead_code)]
    pub fn new_with_options(
        store_path: PathBuf,
        path: PathBuf,
        gpg_backend: GpgBackend,
        allow_create_without_prompt: bool,
    ) -> Result<Self> {
        Self::new_with_options_and_git_sync(
            store_path,
            path,
            gpg_backend,
            allow_create_without_prompt,
            true,
        )
    }

    pub fn new_with_options_and_git_sync(
        store_path: PathBuf,
        path: PathBuf,
        gpg_backend: GpgBackend,
        allow_create_without_prompt: bool,
        git_sync: bool,
    ) -> Result<Self> {
        let inner = InnerPassStorageAdapter::new_with_options(
            store_path.clone(),
            path.clone(),
            gpg_backend,
            allow_create_without_prompt,
        )?;
        let indexed_generation = repository_generation(&store_path, &path);
        let sync = PassGitSync::new(store_path.clone(), git_sync);

        let mut adapter = Self {
            inner,
            store_path,
            path,
            gpg_backend,
            allow_create_without_prompt,
            indexed_generation,
            sync,
        };

        adapter.sync.prepare_startup();
        let generation = repository_generation(&adapter.store_path, &adapter.path);
        if generation != adapter.indexed_generation {
            adapter.reload_from_repository(generation)?;
        }

        Ok(adapter)
    }

    pub fn sync_handle(&self) -> PassGitSync {
        self.sync.clone()
    }

    fn reload_from_repository(&mut self, generation: RepositoryGeneration) -> Result<()> {
        debug!(
            "Reloading pass credential index after repository change: {:?} -> {:?}",
            self.indexed_generation, generation
        );

        let inner = InnerPassStorageAdapter::new_with_options(
            self.store_path.clone(),
            self.path.clone(),
            self.gpg_backend,
            self.allow_create_without_prompt,
        )?;
        self.inner = inner;
        // The constructor may pull newer remote state, so sample again after it returns.
        self.indexed_generation = repository_generation(&self.store_path, &self.path);
        Ok(())
    }

    fn refresh_if_repository_changed(&mut self) -> Result<()> {
        let generation = repository_generation(&self.store_path, &self.path);
        if generation != self.indexed_generation {
            self.reload_from_repository(generation)?;
        }
        Ok(())
    }

    fn prepare_for_access(&mut self) -> Result<()> {
        self.sync.prepare_if_needed();
        self.refresh_if_repository_changed()
    }

    fn record_current_generation(&mut self) {
        self.indexed_generation = repository_generation(&self.store_path, &self.path);
    }

    fn current_credential_count(&self) -> usize {
        self.sync.prepare_if_needed();
        let generation = repository_generation(&self.store_path, &self.path);
        if generation == self.indexed_generation {
            return self.inner.count_credentials();
        }

        load_credential_paths(&self.store_path.join(&self.path), "gpg")
            .map(|indexes| indexes.id.len())
            .unwrap_or_else(|error| {
                warn!(
                    "Failed to count credentials from changed repository state: {}",
                    error
                );
                self.inner.count_credentials()
            })
    }
}

impl CredentialStorage for PassStorageAdapter {
    fn read_first(
        &mut self,
        filter: CredentialFilter,
    ) -> soft_fido2::Result<soft_fido2::Credential> {
        self.refresh_if_repository_changed()
            .map_err(soft_fido2::Error::from)?;
        self.inner.read_first(filter)
    }

    fn read_next(&mut self) -> soft_fido2::Result<soft_fido2::Credential> {
        // Keep an in-progress iteration stable. The next read_first call will
        // reconcile any repository change that happened during this iteration.
        self.inner.read_next()
    }

    fn read(&mut self, id: &[u8]) -> soft_fido2::Result<soft_fido2::Credential> {
        self.refresh_if_repository_changed()
            .map_err(soft_fido2::Error::from)?;
        self.inner.read(id)
    }

    fn write(&mut self, cred: soft_fido2::CredentialRef) -> soft_fido2::Result<()> {
        let implicit = self.sync.begin_implicit_operation();
        if let Err(error) = self.prepare_for_access() {
            if implicit {
                self.sync.end_operation();
            }
            return Err(soft_fido2::Error::from(error));
        }

        let result = self.inner.write(cred);
        if result.is_ok() {
            self.sync.mark_dirty("Update Passless credential state.");
            self.record_current_generation();
        }
        if implicit {
            self.sync.end_operation();
            self.record_current_generation();
        }
        result
    }

    fn delete(&mut self, id: &[u8]) -> soft_fido2::Result<()> {
        let implicit = self.sync.begin_implicit_operation();
        if let Err(error) = self.prepare_for_access() {
            if implicit {
                self.sync.end_operation();
            }
            return Err(soft_fido2::Error::from(error));
        }

        let result = self.inner.delete(id);
        if result.is_ok() {
            self.sync.mark_dirty("Update Passless credential state.");
            self.record_current_generation();
        }
        if implicit {
            self.sync.end_operation();
            self.record_current_generation();
        }
        result
    }

    fn begin_operation(&mut self) -> soft_fido2::Result<()> {
        self.sync.begin_operation();
        Ok(())
    }

    fn end_operation(&mut self) -> soft_fido2::Result<()> {
        self.sync.end_operation();
        self.record_current_generation();
        Ok(())
    }

    fn count_credentials(&self) -> usize {
        self.current_credential_count()
    }

    fn disable_user_verification(&self) -> bool {
        self.inner.disable_user_verification()
    }

    fn cleanup_expired_cache(&mut self) {
        if let Err(error) = self.refresh_if_repository_changed() {
            warn!(
                "Failed to refresh pass credential index after repository change: {}",
                error
            );
        }
        self.inner.cleanup_expired_cache();
    }
}

fn repository_generation(store_path: &Path, credential_path: &Path) -> RepositoryGeneration {
    RepositoryGeneration {
        head: repository_head(store_path),
        credential_tree_stamp: credential_tree_stamp(&store_path.join(credential_path)),
    }
}

fn repository_head(store_path: &Path) -> Option<Oid> {
    let repository = Repository::open(store_path)
        .or_else(|_| Repository::discover(store_path))
        .ok()?;
    repository.head().ok()?.target()
}

fn credential_tree_stamp(root: &Path) -> u64 {
    let mut files = Vec::new();
    let Ok(rp_entries) = fs::read_dir(root) else {
        return 0;
    };

    for rp_entry in rp_entries.flatten() {
        let rp_path = rp_entry.path();
        if !rp_path.is_dir() {
            continue;
        }

        let Ok(credentials) = fs::read_dir(&rp_path) else {
            continue;
        };
        for credential in credentials.flatten() {
            let path = credential.path();
            if path.extension().and_then(|value| value.to_str()) == Some("gpg") {
                files.push(path);
            }
        }
    }

    files.sort();
    let mut hasher = DefaultHasher::new();
    for path in files {
        path.strip_prefix(root).unwrap_or(&path).hash(&mut hasher);
        if let Ok(metadata) = fs::metadata(&path) {
            metadata.len().hash(&mut hasher);
            if let Ok(modified) = metadata.modified()
                && let Ok(duration) = modified.duration_since(UNIX_EPOCH)
            {
                duration.as_nanos().hash(&mut hasher);
            }
        }
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Signature;
    use std::fs;

    fn commit_file(repository: &Repository, relative_path: &Path, contents: &[u8]) -> Oid {
        let workdir = repository.workdir().unwrap();
        let path = workdir.join(relative_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();

        let mut index = repository.index().unwrap();
        index.add_path(relative_path).unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repository.find_tree(tree_id).unwrap();
        let signature = Signature::now("Passless Test", "passless@example.invalid").unwrap();

        let parents = repository
            .head()
            .ok()
            .and_then(|head| head.target())
            .and_then(|oid| repository.find_commit(oid).ok())
            .into_iter()
            .collect::<Vec<_>>();
        let parent_refs = parents.iter().collect::<Vec<_>>();

        repository
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "test commit",
                &tree,
                &parent_refs,
            )
            .unwrap()
    }

    #[test]
    fn generation_changes_when_git_head_moves() {
        let temp = tempfile::tempdir().unwrap();
        let repository = Repository::init(temp.path()).unwrap();
        commit_file(&repository, Path::new("fido2/example.com/01.gpg"), b"first");
        let first = repository_generation(temp.path(), Path::new("fido2"));

        commit_file(
            &repository,
            Path::new("fido2/example.com/02.gpg"),
            b"second",
        );
        let second = repository_generation(temp.path(), Path::new("fido2"));

        assert_ne!(first.head, second.head);
        assert_ne!(first, second);
    }

    #[test]
    fn generation_changes_for_uncommitted_credential_changes() {
        let temp = tempfile::tempdir().unwrap();
        let repository = Repository::init(temp.path()).unwrap();
        commit_file(&repository, Path::new("fido2/example.com/01.gpg"), b"first");
        let first = repository_generation(temp.path(), Path::new("fido2"));

        fs::write(
            temp.path().join("fido2/example.com/01.gpg"),
            b"changed payload with different length",
        )
        .unwrap();
        let second = repository_generation(temp.path(), Path::new("fido2"));

        assert_eq!(first.head, second.head);
        assert_ne!(first.credential_tree_stamp, second.credential_tree_stamp);
    }

    #[test]
    fn generation_changes_when_uncommitted_credential_is_added_or_removed() {
        let temp = tempfile::tempdir().unwrap();
        let repository = Repository::init(temp.path()).unwrap();
        commit_file(&repository, Path::new("fido2/example.com/01.gpg"), b"first");
        let first = repository_generation(temp.path(), Path::new("fido2"));

        let added = temp.path().join("fido2/example.com/02.gpg");
        fs::write(&added, b"second").unwrap();
        let second = repository_generation(temp.path(), Path::new("fido2"));
        assert_ne!(first.credential_tree_stamp, second.credential_tree_stamp);

        fs::remove_file(added).unwrap();
        let third = repository_generation(temp.path(), Path::new("fido2"));
        assert_eq!(first.credential_tree_stamp, third.credential_tree_stamp);
    }
}
