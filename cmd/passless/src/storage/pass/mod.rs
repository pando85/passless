//! Pass (password-store) storage adapter
//!
//! This adapter implements the CredentialStorage trait using prs-lib.
//! Credentials are stored as GPG-encrypted files in the password store.

pub mod init;

use crate::storage::index::{
    CredentialCache, CredentialIndexes, get_credential_path, load_credential_paths,
    update_indexes_on_delete, update_indexes_on_write,
};
use crate::storage::{CredentialFilter, CredentialStorage};
use passless_core::error::{Error, Result};

use soft_fido2::{Credential, CredentialRef, RelyingParty};

use core::fmt;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::time::Instant;

use log::{debug, info, warn};
use prs_lib::crypto::IsContext;
use prs_lib::{Ciphertext, Plaintext, Store};

/// Pass (password-store) storage adapter
///
/// Stores credentials as GPG-encrypted files in a password store directory.
/// Uses prs-lib for password store operations.
pub struct PassStorageAdapter {
    store_path: PathBuf,
    path: PathBuf,
    gpg_backend: GpgBackend,
    indexes: CredentialIndexes,
    /// Time-limited cache: file_path -> (credential, expiry_time)
    /// Credentials are automatically evicted after CREDENTIAL_CACHE_TTL
    cache: CredentialCache,
    iteration_index: usize,
    iteration_entries: Vec<PathBuf>,
}

/// GPG backend selection for encryption/decryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpgBackend {
    /// Use GPGME library (if available)
    Gpgme,
    /// Use GnuPG binary
    #[default]
    GnupgBin,
}

impl GpgBackend {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "gpgme" => Ok(Self::Gpgme),
            "gnupg-bin" | "gnupg_bin" | "gnupg" => Ok(Self::GnupgBin),
            _ => Err(Error::Config(format!("Invalid GPG backend: {}", s))),
        }
    }
}

impl Display for GpgBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GpgBackend::Gpgme => write!(f, "gpgme"),
            GpgBackend::GnupgBin => write!(f, "gpg"),
        }
    }
}

impl PassStorageAdapter {
    /// Create a new pass storage adapter
    ///
    /// # Arguments
    ///
    /// * `store_path` - Root directory of the password store (not including fido2 subdir)
    /// * `gpg_backend` - GPG backend selection
    ///
    /// # Returns
    ///
    /// A new PassStorageAdapter instance
    ///
    /// # Note
    ///
    /// If the password store is not initialized, this will prompt the user
    /// via desktop notifications to initialize it.
    pub fn new(store_path: PathBuf, path: PathBuf, gpg_backend: GpgBackend) -> Result<Self> {
        info!("Using pass (password-store) backend");
        info!("Store path: {}", store_path.display());
        info!("Path: {}", path.display());
        info!("GPG backend: {}", gpg_backend);

        debug!("Opening password store at: {:?}", store_path);

        // Ensure the password store is initialized
        // This will prompt the user via notifications if not initialized
        self::init::ensure_initialized(&store_path, gpg_backend)?;

        if !store_path.exists() {
            return Err(Error::Storage(format!(
                "Password store path does not exist: {:?}",
                store_path
            )));
        }

        debug!("Using GPG backend: {:?}", gpg_backend);

        let mut adapter = Self {
            store_path,
            path,
            gpg_backend,
            indexes: Default::default(),
            cache: Default::default(),
            iteration_index: Default::default(),
            iteration_entries: Default::default(),
        };

        // Pull latest changes from git remote if configured
        adapter.sync_prepare()?;

        // Load indexes by scanning directory structure (no decryption!)
        adapter.indexes = load_credential_paths(&adapter.get_fido2_path(), "gpg")
            .map_err(|e| Error::Storage(format!("Failed to load credential paths: {}", e)))?;

        Ok(adapter)
    }

    /// Get the FIDO path within the password store
    fn get_fido2_path(&self) -> PathBuf {
        self.store_path.join(&self.path)
    }

    /// Prepare the store for changes (pulls from git remote if configured)
    fn sync_prepare(&self) -> Result<()> {
        debug!("Preparing password store sync");

        let store = Store::open(self.store_path.to_string_lossy().as_ref()).map_err(|e| {
            debug!("Failed to open store for sync: {:?}", e);
            Error::Storage(format!("Failed to open store for sync: {:?}", e))
        })?;

        let sync = store.sync();

        match sync.prepare() {
            Ok(()) => {
                debug!("Successfully prepared store sync (pulled if remote configured)");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to prepare store sync: {:?}", e);
                Ok(())
            }
        }
    }

    /// Finalize changes to the store (commits and pushes to git remote if configured)
    fn sync_finalize(&self, message: &str) -> Result<()> {
        debug!("Finalizing password store sync: {}", message);

        let store = Store::open(self.store_path.to_string_lossy().as_ref()).map_err(|e| {
            debug!("Failed to open store for sync: {:?}", e);
            Error::Storage(format!("Failed to open store for sync: {:?}", e))
        })?;

        let sync = store.sync();

        match sync.finalize(message) {
            Ok(()) => {
                debug!(
                    "Successfully finalized store sync (committed and pushed if remote configured)"
                );
                Ok(())
            }
            Err(e) => {
                debug!("Failed to finalize store sync: {:?}", e);
                // Don't fail the operation if sync fails, just log a warning
                warn!("Failed to finalize store sync: {:?}", e);
                Ok(())
            }
        }
    }

    /// Create a crypto context based on the configured backend
    fn create_crypto_context(&self) -> Result<prs_lib::crypto::Context> {
        let proto = match self.gpg_backend {
            GpgBackend::Gpgme | GpgBackend::GnupgBin => prs_lib::crypto::Proto::Gpg,
        };

        let config = prs_lib::crypto::Config::from(proto);
        debug!("Creating crypto context with protocol: {:?}", proto);

        prs_lib::crypto::context(&config).map_err(|e| {
            debug!("Failed to create crypto context: {:?}", e);
            Error::Storage(format!("Failed to create crypto context: {:?}", e))
        })
    }

    /// Read a credential from a specific file path WITHOUT caching
    /// Used for operations that need &self (select_users, get_relying_parties, etc.)
    #[allow(dead_code)]
    fn read_credential_from_path_no_cache(&self, path: &Path) -> Result<Credential> {
        debug!("Reading credential (no cache) from path: {:?}", path);

        // Read the encrypted GPG file
        let encrypted_data = std::fs::read(path).map_err(|e| {
            debug!("Failed to read encrypted file: {}", e);
            Error::Storage(format!("Failed to read file: {}", e))
        })?;

        // Create crypto context
        let mut context = self.create_crypto_context()?;

        // Decrypt the data
        let ciphertext = Ciphertext::from(encrypted_data);
        let plaintext = context.decrypt(ciphertext).map_err(|e| {
            debug!("Failed to decrypt credential: {:?}", e);
            Error::Storage(format!("Failed to decrypt credential: {:?}", e))
        })?;

        debug!("Successfully decrypted credential");

        // Parse credential from decrypted bytes
        serde_json::from_slice(plaintext.unsecure_ref())
            .map_err(|e| Error::Storage(format!("Failed to parse credential: {:?}", e)))
    }

    /// Read a credential from a specific file path
    /// Uses time-limited cache to avoid redundant GPG decryption
    fn read_credential_from_path(&mut self, path: &Path) -> Result<Credential> {
        if let Some(cached) = self.cache.get(path) {
            if Instant::now() < cached.expires_at {
                debug!("Cache HIT for path: {:?}", path);
                return Ok(cached.credential.clone());
            } else {
                debug!("Cache entry expired for path: {:?}", path);
            }
        }

        debug!(
            "Cache MISS - reading and decrypting credential from path: {:?}",
            path
        );

        // Evict expired entries before adding new one
        self.cache.evict_expired();

        // If cache is full, evict oldest entry
        self.cache.evict_oldest_if_full();

        // Read the encrypted GPG file
        let encrypted_data = std::fs::read(path).map_err(|e| {
            debug!("Failed to read encrypted file: {}", e);
            Error::Storage(format!("Failed to read file: {}", e))
        })?;

        // Create crypto context
        let mut context = self.create_crypto_context()?;

        // Decrypt the data
        let ciphertext = Ciphertext::from(encrypted_data);
        let plaintext = context.decrypt(ciphertext).map_err(|e| {
            debug!("Failed to decrypt credential: {:?}", e);
            Error::Storage(format!("Failed to decrypt credential: {:?}", e))
        })?;

        debug!("Successfully decrypted credential");

        // Parse credential from decrypted bytes
        let credential: Credential = serde_json::from_slice(plaintext.unsecure_ref())
            .map_err(|e| Error::Storage(format!("Failed to parse credential: {:?}", e)))?;

        // Cache the decrypted credential with automatic TTL
        self.cache.insert(path.to_path_buf(), credential.clone());

        Ok(credential)
    }

    /// Read a credential by its ID
    fn read_credential_by_id(&mut self, id: &[u8]) -> Result<Credential> {
        debug!("Reading credential by ID: {:02x?}", &id[..id.len().min(8)]);

        let path = self
            .indexes
            .id
            .get(id)
            .ok_or_else(|| {
                debug!("Credential not found in index");
                Error::Storage("Credential not found".to_string())
            })?
            .clone();

        self.read_credential_from_path(&path)
    }

    /// Load GPG recipients from .gpg-id file
    /// This bypasses prs-lib's Recipients::load which tries to read .public-keys
    fn load_recipients_from_gpg_id(&self) -> Result<prs_lib::Recipients> {
        let gpg_id_path = &self.store_path.join(".gpg-id");
        debug!("Checking for .gpg-id at: {:?}", gpg_id_path);
        match std::fs::read_to_string(gpg_id_path) {
            Ok(content) => {
                debug!("Found .gpg-id at: {:?}", gpg_id_path);
                self.parse_gpg_id_content(&content, gpg_id_path)
            }
            Err(e) => {
                debug!("Failed to read .gpg-id at {:?}: {}", gpg_id_path, e);
                Err(Error::Storage(format!(
                    "Failed to find .gpg-id file in {:?} or any parent directory. Make sure the password store is initialized with: pass init <gpg-key-id>",
                    self.store_path
                )))
            }
        }
    }

    /// Parse GPG key IDs from .gpg-id file content
    fn parse_gpg_id_content(
        &self,
        content: &str,
        gpg_id_path: &Path,
    ) -> Result<prs_lib::Recipients> {
        // Parse key IDs from .gpg-id (one per line, skip empty lines and comments)
        let keys: Vec<prs_lib::Key> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|key_id| {
                debug!("Found GPG key ID: {}", key_id);
                // Create a GPG key with just the fingerprint
                // prs-lib will handle key validation when encrypting
                let gpg_key = prs_lib::crypto::proto::gpg::Key {
                    fingerprint: key_id.to_string(),
                    user_ids: vec![],
                };
                prs_lib::Key::Gpg(gpg_key)
            })
            .collect();

        if keys.is_empty() {
            return Err(Error::Storage(format!(
                "No GPG key IDs found in .gpg-id file at {:?}",
                gpg_id_path
            )));
        }

        debug!(
            "Loaded {} GPG recipient(s) from {:?}",
            keys.len(),
            gpg_id_path
        );
        Ok(prs_lib::Recipients::from(keys))
    }

    /// Write a credential to the store
    fn write_credential(&mut self, cred: &Credential, cred_json: &str) -> Result<()> {
        self.cache.evict_expired();

        let path = get_credential_path(&self.get_fido2_path(), &cred.rp.id, &cred.id, "gpg");
        debug!("Writing credential to: {:?}", path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                debug!("Failed to create directory: {}", e);
                Error::Storage(format!("Failed to create directory: {}", e))
            })?;
        }

        // Load recipients from .gpg-id file
        let recipients = self.load_recipients_from_gpg_id()?;

        // Create crypto context
        let mut context = self.create_crypto_context()?;

        // Encrypt and write the credential data directly to file
        let plaintext = Plaintext::from(cred_json);

        context
            .encrypt_file(&recipients, plaintext, &path)
            .map_err(|e| {
                debug!("Failed to encrypt credential: {:?}", e);
                Error::Storage(format!("Failed to encrypt credential: {:?}", e))
            })?;

        debug!("Successfully wrote and encrypted credential");

        // Invalidate cache entry for this credential to ensure fresh reads
        self.cache.remove(&path);

        // Update all indexes using shared function
        update_indexes_on_write(
            &mut self.indexes,
            path.clone(),
            cred.id.to_vec(),
            cred.rp.id.clone(),
        );

        // Commit and push changes to git remote if configured
        let relative_path = path
            .strip_prefix(&self.store_path)
            .unwrap_or(&path)
            .display();
        let commit_message = format!("Add generated password for {}.", relative_path);
        self.sync_finalize(&commit_message)?;

        Ok(())
    }

    /// Delete a credential from the store
    fn delete_credential(&mut self, id: &[u8]) -> Result<()> {
        self.cache.evict_expired();

        debug!(
            "Deleting credential with ID: {:02x?}",
            &id[..id.len().min(8)]
        );

        let path = self
            .indexes
            .id
            .get(id)
            .ok_or_else(|| {
                debug!("Credential not found in index");
                Error::Storage("Credential not found".to_string())
            })?
            .clone();

        // Read credential to get RP info for index cleanup
        let cred = self.read_credential_from_path(&path)?;

        // Delete the file
        std::fs::remove_file(&path).map_err(|e| {
            debug!("Failed to delete file: {}", e);
            Error::Storage(format!("Failed to delete file: {}", e))
        })?;

        // Remove from cache
        self.cache.remove(&path);

        // Remove from all indexes using shared function
        update_indexes_on_delete(&mut self.indexes, &path, id, &cred.rp.id);

        debug!("Successfully deleted credential");

        // Commit and push changes to git remote if configured
        let relative_path = path
            .strip_prefix(&self.store_path)
            .unwrap_or(&path)
            .display();
        let commit_message = format!("Remove {} from store.", relative_path);
        self.sync_finalize(&commit_message)?;

        Ok(())
    }

    /// Load all credentials from the store (non-caching version)
    /// Used for operations that need &self
    #[allow(dead_code)]
    fn load_all_credentials_no_cache(&self) -> Vec<Credential> {
        debug!("Loading all credentials from store (no cache)");
        let mut credentials = Vec::new();

        for path in self.indexes.id.values() {
            if let Ok(cred) = self.read_credential_from_path_no_cache(path) {
                credentials.push(cred);
            }
        }

        debug!("Loaded {} credentials", credentials.len());
        credentials
    }

    /// Find the next credential matching the current filter
    /// Uses indexes for efficient lookup
    fn find_next(&mut self) -> Result<Credential> {
        debug!(
            "Finding next credential (index: {}/{})",
            self.iteration_index,
            self.iteration_entries.len()
        );

        if self.iteration_index >= self.iteration_entries.len() {
            debug!("No more credentials matching filter");
            return Err(Error::Storage("No more credentials".to_string()));
        }

        let path = self.iteration_entries[self.iteration_index].clone();
        self.iteration_index += 1;

        self.read_credential_from_path(&path)
    }
}

impl CredentialStorage for PassStorageAdapter {
    fn read_first(&mut self, filter: CredentialFilter) -> soft_fido2::Result<Credential> {
        self.cache.evict_expired();

        debug!("read_first called with filter: {:?}", filter);

        // Initialize iteration using the appropriate index
        self.iteration_entries = match &filter {
            CredentialFilter::None => {
                // No filter: iterate all credentials
                self.indexes.id.values().cloned().collect()
            }
            CredentialFilter::ById(id) => {
                // ById: direct lookup in index_by_id
                if let Some(path) = self.indexes.id.get(id.as_slice()) {
                    vec![path.clone()]
                } else {
                    Vec::new()
                }
            }
            CredentialFilter::ByRp(rp_id) => {
                // ByRp: lookup in index_by_rp
                if let Some(paths) = self.indexes.rp.get(rp_id.as_str()) {
                    paths.clone()
                } else {
                    Vec::new()
                }
            }
            CredentialFilter::ByHash(hash) => {
                // ByHash: lookup in index_by_rp_hash
                if let Some(paths) = self.indexes.rp_hash.get(hash) {
                    paths.clone()
                } else {
                    Vec::new()
                }
            }
        };

        self.iteration_index = 0;

        debug!(
            "Starting iteration with {} entries for filter: {:?}",
            self.iteration_entries.len(),
            filter
        );

        self.find_next().map_err(Into::into)
    }

    fn read_next(&mut self) -> soft_fido2::Result<Credential> {
        self.cache.evict_expired();

        debug!("read_next called");
        self.find_next().map_err(Into::into)
    }

    fn read(&mut self, id: &[u8], _rp: &str) -> soft_fido2::Result<Vec<u8>> {
        self.cache.evict_expired();

        debug!("read called with id: {}", hex::encode(id));

        let cred = self.read_credential_by_id(id).map_err(|e| {
            debug!("Failed to read credential: {:?}", e);
            e
        })?;

        cred.to_bytes()
    }

    fn write(&mut self, _id: &[u8], _rp: &str, cred_ref: CredentialRef) -> soft_fido2::Result<()> {
        self.cache.evict_expired();

        debug!("write called for RP: {}", cred_ref.rp_id);

        let credential = cred_ref.to_owned();
        let cred_json = serde_json::to_string(&credential).map_err(|e| {
            debug!("Failed to serialize credential: {:?}", e);
            Error::Storage(format!("Failed to serialize credential: {:?}", e))
        })?;
        self.write_credential(&credential, &cred_json)
            .map_err(Into::into)
    }

    fn delete(&mut self, id: &[u8]) -> soft_fido2::Result<()> {
        self.cache.evict_expired();

        debug!("delete called with id: {}", hex::encode(id));
        self.delete_credential(id).map_err(Into::into)
    }

    fn select_users(&self, rp_id: &str) -> Vec<String> {
        debug!("select_users called for RP: {}", rp_id);

        let credentials = self.load_all_credentials_no_cache();
        let users: Vec<String> = credentials
            .iter()
            .filter(|cred| cred.rp.id == rp_id)
            .map(|cred| String::from_utf8_lossy(&cred.user.id).to_string())
            .collect();

        debug!("Found {} users for RP: {}", users.len(), rp_id);
        users
    }

    fn count_credentials(&self) -> usize {
        let count = self.indexes.id.len();
        debug!("count_credentials: {}", count);
        count
    }

    fn get_relying_parties(&self) -> soft_fido2::Result<Vec<RelyingParty>> {
        debug!("get_relying_parties called");

        let credentials = self.load_all_credentials_no_cache();

        let rp_list: Vec<RelyingParty> = credentials.into_iter().map(|c| c.rp).collect();
        debug!("Found {} relying parties", rp_list.len());
        Ok(rp_list)
    }

    fn disable_user_verification(&self) -> bool {
        // Pass backend doesn't support user verification
        true
    }

    fn cleanup_expired_cache(&mut self) {
        self.cache.evict_expired();
    }
}
