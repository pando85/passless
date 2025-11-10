//! Local file system storage adapter
//!
//! This adapter implements the CredentialStorage trait using the local file system.

use crate::storage::{CredentialFilter, CredentialStorage};

use keylib::credential::RelyingParty;
use keylib::{Credential, CredentialRef, Result};

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use log::info;
use sha2::{Digest, Sha256};

/// Local file system storage adapter
///
/// Stores credentials as individual files in a directory.
pub struct LocalStorageAdapter {
    storage_dir: PathBuf,
    iteration_index: usize,
    iteration_files: Vec<PathBuf>,
    iteration_filter: CredentialFilter,
}

impl LocalStorageAdapter {
    /// Create a new local storage adapter
    ///
    /// # Arguments
    ///
    /// * `storage_dir` - Directory path where credentials will be stored
    ///
    /// # Returns
    ///
    /// A new LocalStorageAdapter instance
    pub fn new(storage_dir: PathBuf) -> Result<Self> {
        info!("Using local file system backend");
        info!("Storage path: {}", storage_dir.display());
        fs::create_dir_all(&storage_dir).map_err(|_| keylib::Error::Other)?;

        Ok(Self {
            storage_dir,
            iteration_index: 0,
            iteration_files: Vec::new(),
            iteration_filter: CredentialFilter::None,
        })
    }

    /// Load all credentials from storage
    fn load_all_credentials(&self) -> Vec<Credential> {
        let mut credentials = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.storage_dir) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type()
                    && file_type.is_file()
                    && let Ok(cred) = self.load_credential(&entry.path())
                {
                    credentials.push(cred);
                }
            }
        }

        credentials
    }

    /// Load a credential from a file
    fn load_credential(&self, path: &PathBuf) -> Result<Credential> {
        let mut file = File::open(path).map_err(|_| keylib::Error::DoesNotExist)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|_| keylib::Error::Other)?;

        Credential::from_bytes(&contents)
    }

    /// Save a credential to a file
    fn save_credential(&self, cred: &Credential) -> Result<()> {
        let filename = self.get_filename_for_cred(&cred.user.id);
        let path = self.storage_dir.join(filename);

        let bytes = cred.to_bytes()?;

        let mut file = File::create(&path).map_err(|_| keylib::Error::Other)?;
        file.write_all(&bytes).map_err(|_| keylib::Error::Other)?;

        Ok(())
    }

    /// Generate a filename for a credential based on user ID
    fn get_filename_for_cred(&self, user_id: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(user_id);
        let hash: [u8; 32] = hasher.finalize().into();
        format!(
            "cred_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
        )
    }

    /// Find the next credential matching the current filter
    fn find_next(&mut self) -> Result<Credential> {
        while self.iteration_index < self.iteration_files.len() {
            let path = &self.iteration_files[self.iteration_index];
            self.iteration_index += 1;

            if let Ok(loaded_cred) = self.load_credential(path) {
                let matches = self.matches_filter(&loaded_cred);

                if matches {
                    return Ok(loaded_cred);
                }
            }
        }

        Err(keylib::Error::DoesNotExist)
    }

    /// Check if a credential matches the current filter
    fn matches_filter(&self, cred: &Credential) -> bool {
        match &self.iteration_filter {
            CredentialFilter::None => true,
            CredentialFilter::ById(id) => &cred.id == id,
            CredentialFilter::ByRp(rp) => &cred.rp.id == rp,
            CredentialFilter::ByHash(hash) => {
                let mut hasher = Sha256::new();
                hasher.update(cred.rp.id.as_bytes());
                let rp_hash: [u8; 32] = hasher.finalize().into();
                &rp_hash == hash
            }
        }
    }
}

impl CredentialStorage for LocalStorageAdapter {
    fn read_first(&mut self, filter: CredentialFilter) -> Result<Credential> {
        // Reset iteration
        self.iteration_index = 0;
        self.iteration_files.clear();
        self.iteration_filter = filter;

        // Load all credential file paths
        if let Ok(entries) = fs::read_dir(&self.storage_dir) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type()
                    && file_type.is_file()
                {
                    self.iteration_files.push(entry.path());
                }
            }
        }

        // Find first matching credential
        self.find_next()
    }

    fn read_next(&mut self) -> Result<Credential> {
        self.find_next()
    }

    fn read(&mut self, id: &str, rp: &str) -> Result<Vec<u8>> {
        let cred = self.read_first(CredentialFilter::ById(id.as_bytes().to_vec()))?;
        if cred.rp.id != rp {
            return Err(keylib::Error::DoesNotExist);
        }
        cred.to_bytes()
    }

    fn write(&mut self, _id: &str, _rp: &str, cred_ref: CredentialRef) -> Result<()> {
        let mut cred = cred_ref.to_owned();
        cred.sign_count = 0;
        cred.created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        cred.discoverable = true;

        self.save_credential(&cred)
    }

    fn delete(&mut self, id: &str) -> Result<()> {
        let id_bytes = id.as_bytes();

        let credentials = self.load_all_credentials();
        for cred in credentials {
            if cred.id == id_bytes {
                let filename = self.get_filename_for_cred(&cred.user.id);
                let path = self.storage_dir.join(filename);
                fs::remove_file(path).map_err(|_| keylib::Error::Other)?;
                return Ok(());
            }
        }

        Err(keylib::Error::DoesNotExist)
    }

    fn select_users(&self, rp_id: &str) -> Vec<String> {
        self.load_all_credentials()
            .iter()
            .filter(|cred| cred.rp.id == rp_id)
            .map(|cred| String::from_utf8_lossy(&cred.user.id).to_string())
            .collect()
    }

    fn count_credentials(&self) -> usize {
        self.load_all_credentials().len()
    }

    fn get_relying_parties(&self) -> Result<Vec<RelyingParty>> {
        let credentials = self.load_all_credentials();
        Ok(credentials.into_iter().map(|c| c.rp).collect())
    }
}
