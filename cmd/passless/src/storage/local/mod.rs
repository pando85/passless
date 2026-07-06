//! Local file system storage adapter

pub mod init;

use crate::storage::credential::Credential;
use crate::storage::index::{
    CredentialIndexes, CredentialPathInfo, load_credential_paths, update_indexes_on_delete,
    update_indexes_on_write,
};
use crate::storage::{CredentialFilter, CredentialStorage};
use crate::util::{create_secure_dir_all, create_secure_file};

use soft_fido2::Result;

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use log::{debug, info, warn};
use zeroize::Zeroizing;

/// Local file system storage adapter
///
/// Stores credentials as files in a hierarchical directory structure.
/// File structure: {storage_dir}/{rp_id}/{cred_id_hex}.bin
/// Uses indexes for efficient lookups without loading all credentials.
pub struct LocalStorageAdapter {
    storage_dir: PathBuf,
    indexes: CredentialIndexes,
    iteration_index: usize,
    iteration_files: Vec<PathBuf>,
}

impl LocalStorageAdapter {
    /// Create a new local storage adapter
    pub fn new(storage_dir: PathBuf) -> Result<Self> {
        info!("Using local file system backend");
        info!("Storage path: {}", storage_dir.display());

        // Validate storage directory path
        if storage_dir.is_absolute() {
            warn!("Storage path is absolute: {}", storage_dir.display());
        } else {
            debug!("Storage path is relative: {}", storage_dir.display());
        }

        // Ensure the storage directory is initialized
        // This will prompt the user via notifications if not initialized
        self::init::ensure_initialized(&storage_dir).map_err(|_| soft_fido2::Error::Other)?;

        // Load indexes from directory structure (no credential loading needed)
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

    /// Load a credential from a file path
    fn load_credential_from_path(&self, path: &Path) -> Result<soft_fido2::Credential> {
        debug!("Loading credential from: {:?}", path);
        let mut file = fs::File::open(path).map_err(|_| soft_fido2::Error::DoesNotExist)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|_| soft_fido2::Error::Other)?;

        // Load using auto format (tries our format, falls back to soft-fido2 format)
        Credential::from_bytes(&contents).map(|cred| cred.to_soft_fido2())
    }

    /// Save a credential to a file
    /// Uses hierarchical structure: {storage_dir}/{rp_id}/{cred_id_hex}.bin
    fn save_credential(&mut self, cred: &soft_fido2::Credential) -> Result<()> {
        // Convert to our format for controlled serialization
        let our_cred = Credential::from_soft_fido2(cred);

        // Create path info for this credential
        let path_info =
            CredentialPathInfo::new(cred.rp.id.clone(), cred.id.clone(), "bin".to_string());

        let path = path_info.to_path(&self.storage_dir);

        // Ensure the RP directory exists with secure permissions
        if let Some(parent) = path.parent() {
            create_secure_dir_all(parent).map_err(|_| soft_fido2::Error::Other)?;
        }

        // Use Zeroizing to ensure credential bytes are cleared from memory after use
        let bytes = Zeroizing::new(our_cred.to_bytes()?);

        let mut file = create_secure_file(&path).map_err(|_| soft_fido2::Error::Other)?;
        file.write_all(&bytes)
            .map_err(|_| soft_fido2::Error::Other)?;

        // bytes is automatically zeroed when it goes out of scope

        // Update indexes
        update_indexes_on_write(&mut self.indexes, path_info);

        debug!("Saved credential for RP: {}", cred.rp.id);
        Ok(())
    }

    /// Find the next credential matching the current filter
    /// Uses indexes for efficient lookup
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

        // Use index for direct path lookup
        let path_info = self
            .indexes
            .id
            .get(id)
            .ok_or(soft_fido2::Error::DoesNotExist)?;

        let path = path_info.to_path(&self.storage_dir);
        // Load and return credential directly (no re-serialization)
        self.load_credential_from_path(&path)
    }

    fn write(&mut self, cred_ref: soft_fido2::CredentialRef) -> Result<()> {
        // Just save the credential as provided by soft-fido2
        // This is called both during registration (new credential) and
        // during authentication (updating sign counter)
        let cred = cred_ref.to_owned();
        self.save_credential(&cred)
    }

    fn delete(&mut self, id: &[u8]) -> Result<()> {
        debug!("delete called for credential ID");

        // Use index for direct path lookup
        let path_info = self
            .indexes
            .id
            .get(id)
            .ok_or(soft_fido2::Error::DoesNotExist)?;

        let path = path_info.to_path(&self.storage_dir);
        let rp_id = path_info.rp_id.clone();

        // Delete the file
        fs::remove_file(&path).map_err(|_| soft_fido2::Error::Other)?;

        // Update indexes (extracts RP ID from path info internally)
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
