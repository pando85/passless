//! Local file system storage adapter

pub mod init;

use crate::storage::credential::Credential;
use crate::storage::index::{
    CredentialIndexes, CredentialPathInfo, load_credential_paths, update_indexes_on_delete,
    update_indexes_on_write,
};
use crate::storage::rp_id::ValidatedRpId;
use crate::storage::{CredentialFilter, CredentialStorage};
use crate::util::{atomic_write_in_dir, create_secure_dir_all};

use soft_fido2::Result;

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use log::{debug, error, info, warn};
use zeroize::Zeroizing;

pub struct LocalStorageAdapter {
    storage_dir: PathBuf,
    indexes: CredentialIndexes,
    iteration_index: usize,
    iteration_files: Vec<PathBuf>,
}

impl LocalStorageAdapter {
    #[cfg(test)]
    pub fn new(storage_dir: PathBuf) -> Result<Self> {
        Self::new_with_options(storage_dir, true)
    }

    pub fn new_with_options(
        storage_dir: PathBuf,
        allow_create_without_prompt: bool,
    ) -> Result<Self> {
        let allow_create_without_prompt = cfg!(debug_assertions) && allow_create_without_prompt;
        info!("Using local file system backend");
        info!("Storage path: {}", storage_dir.display());

        if storage_dir.is_absolute() {
            warn!("Storage path is absolute: {}", storage_dir.display());
        } else {
            debug!("Storage path is relative: {}", storage_dir.display());
        }

        self::init::ensure_initialized(&storage_dir, allow_create_without_prompt)
            .map_err(|_| soft_fido2::Error::Other)?;

        let indexes =
            load_credential_paths(&storage_dir, "bin").map_err(|_| soft_fido2::Error::Other)?;

        debug!("Loaded {} credentials into indexes", indexes.id.len());

        Ok(Self {
            storage_dir,
            indexes,
            iteration_index: 0,
            iteration_files: Vec::new(),
        })
    }

    fn load_credential_from_path(&self, path: &Path) -> Result<soft_fido2::Credential> {
        debug!("Loading credential from: {:?}", path);
        let mut file = fs::File::open(path).map_err(|_| soft_fido2::Error::DoesNotExist)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|_| soft_fido2::Error::Other)?;

        Credential::from_bytes(&contents).map(|cred| cred.to_soft_fido2())
    }

    fn save_credential(&mut self, cred: &soft_fido2::Credential) -> Result<()> {
        let our_cred = Credential::from_soft_fido2(cred);

        let rp_id = ValidatedRpId::try_from(cred.rp.id.as_str()).map_err(|e| {
            error!(
                "Rejected credential with invalid RP ID '{}': {}",
                cred.rp.id, e
            );
            soft_fido2::Error::Other
        })?;

        let path_info = CredentialPathInfo::new(rp_id, cred.id.clone(), "bin".to_string());

        let path = path_info.to_path(&self.storage_dir);

        let parent = path.parent().ok_or(soft_fido2::Error::Other)?;
        create_secure_dir_all(parent).map_err(|e| {
            error!(
                "Failed to create credential directory {}: {}",
                parent.display(),
                e
            );
            soft_fido2::Error::Other
        })?;

        let bytes = Zeroizing::new(our_cred.to_bytes()?);

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(soft_fido2::Error::Other)?;
        atomic_write_in_dir(parent, filename, &bytes).map_err(|e| {
            error!("Failed to persist credential {}: {}", path.display(), e);
            soft_fido2::Error::Other
        })?;

        update_indexes_on_write(&mut self.indexes, path_info);

        debug!("Saved credential for RP: {}", cred.rp.id);
        Ok(())
    }

    fn find_next(&mut self) -> Result<soft_fido2::Credential> {
        debug!(
            "Finding next credential (index: {}/{})",
            self.iteration_index,
            self.iteration_files.len()
        );

        if self.iteration_index >= self.iteration_files.len() {
            debug!("No more credentials matching filter");
            return Err(soft_fido2::Error::DoesNotExist);
        }

        let path = &self.iteration_files[self.iteration_index];
        self.iteration_index += 1;

        self.load_credential_from_path(path)
    }
}

impl CredentialStorage for LocalStorageAdapter {
    fn read_first(&mut self, filter: CredentialFilter) -> Result<soft_fido2::Credential> {
        debug!("read_first called with filter: {:?}", filter);

        self.iteration_index = 0;
        self.iteration_files = self.indexes.resolve_filter(&filter, &self.storage_dir);

        debug!("Found {} matching paths", self.iteration_files.len());

        self.find_next()
    }

    fn read_next(&mut self) -> Result<soft_fido2::Credential> {
        self.find_next()
    }

    fn read(&mut self, id: &[u8]) -> Result<soft_fido2::Credential> {
        debug!("read called for credential ID");

        let path_info = self
            .indexes
            .id
            .get(id)
            .ok_or(soft_fido2::Error::DoesNotExist)?;

        let path = path_info.to_path(&self.storage_dir);
        self.load_credential_from_path(&path)
    }

    fn write(&mut self, cred_ref: soft_fido2::CredentialRef) -> Result<()> {
        let cred = cred_ref.to_owned();
        self.save_credential(&cred)
    }

    fn delete(&mut self, id: &[u8]) -> Result<()> {
        debug!("delete called for credential ID");

        let path_info = self
            .indexes
            .id
            .get(id)
            .ok_or(soft_fido2::Error::DoesNotExist)?;

        let path = path_info.to_path(&self.storage_dir);
        let rp_id = path_info.rp_id.clone();

        fs::remove_file(&path).map_err(|_| soft_fido2::Error::Other)?;

        update_indexes_on_delete(&mut self.indexes, id);

        debug!("Deleted credential for RP: {}", rp_id);
        Ok(())
    }

    fn count_credentials(&self) -> usize {
        let count = self.indexes.id.len();
        debug!("count_credentials: {}", count);
        count
    }
}
