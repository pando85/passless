//! Pass (password-store) storage adapter
//!
//! This adapter implements the CredentialStorage trait using prs-lib.
//! Credentials are stored as GPG-encrypted files in the password store.

use crate::error::{Error, Result};
use crate::storage::{CredentialFilter, CredentialStorage};

use keylib::credential::RelyingParty;
use keylib::{Credential, CredentialRef};

use core::fmt;
use std::collections::HashMap;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use log::{debug, info};
use prs_lib::crypto::IsContext;
use prs_lib::{Ciphertext, Plaintext};

/// Time-to-live for cached credentials (30 seconds)
/// Short enough to minimize exposure, long enough for a single auth flow
const CREDENTIAL_CACHE_TTL: Duration = Duration::from_secs(30);

/// Maximum number of cached credentials (prevents unbounded memory growth)
const MAX_CACHE_SIZE: usize = 10;

/// Cached credential with expiration time
struct CachedCredential {
    credential: Credential,
    expires_at: Instant,
}

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
    cache: HashMap<PathBuf, CachedCredential>,
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
    /// Assumes the password store is already initialized.
    /// Use `pass init <gpg-key>` to initialize the store before using this adapter.
    pub fn new(store_path: PathBuf, path: PathBuf, gpg_backend: GpgBackend) -> Result<Self> {
        info!("Using pass (password-store) backend");
        info!("Store path: {}", store_path.display());
        info!("Path: {}", path.display());
        info!("GPG backend: {}", gpg_backend);

        debug!("Opening password store at: {:?}", store_path);
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

        adapter.indexes = adapter.load_credential_paths()?;

        Ok(adapter)
    }

    /// Get the filename for a credential based on credential ID
    /// Format: {cred_id_hex}.gpg
    /// The credential ID is hex-encoded for safe, unique filenames
    fn get_filename(cred_id: &[u8]) -> String {
        let cred_id_hex: String = cred_id.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}.gpg", cred_id_hex)
    }

    /// Parse credential ID from filename
    /// Returns None if filename doesn't match expected format
    fn parse_cred_id_from_filename(filename: &str) -> Option<Vec<u8>> {
        // Remove .gpg extension
        let name = filename.strip_suffix(".gpg")?;

        // Decode hex string to bytes
        if name.len() % 2 != 0 {
            return None; // Invalid hex (must be even length)
        }

        let mut bytes = Vec::with_capacity(name.len() / 2);
        for i in (0..name.len()).step_by(2) {
            let byte = u8::from_str_radix(&name[i..i + 2], 16).ok()?;
            bytes.push(byte);
        }

        Some(bytes)
    }

    /// Get the FIDO path within the password store
    fn get_fido2_path(&self) -> PathBuf {
        self.store_path.join(&self.path)
    }

    /// Get the full path for a credential file
    /// Structure: {store_path}/{rp_id}/{cred_id_hex}.gpg
    fn get_credential_path(&self, rp_id: &str, cred_id: &[u8]) -> PathBuf {
        self.get_fido2_path()
            .join(rp_id)
            .join(Self::get_filename(cred_id))
    }

    /// Load all credential paths into the indexes
    /// Scans directories (rp_id) and files (cred_id_hex.gpg) within
    /// Builds three indexes: by credential ID, by RP ID, and by RP hash
    /// NO DECRYPTION NEEDED - credential ID is extracted from filename
    /// Returns the built indexes as a functional result
    fn load_credential_paths(&self) -> Result<CredentialIndexes> {
        debug!("Loading credential paths from store (functional approach)");

        // List all directories in the store (each directory is an rp_id)
        let entries = match std::fs::read_dir(self.get_fido2_path()) {
            Ok(entries) => entries,
            Err(e) => {
                debug!("Failed to read store directory: {}", e);
                return Ok(CredentialIndexes::default());
            }
        };

        // Collect all valid RP directories
        let rp_dirs: Vec<(String, PathBuf)> = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let path = entry.path();
                // Skip files, .gpg-id, .public-keys, and hidden directories
                if !path.is_dir()
                    || path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s.starts_with('.'))
                {
                    return None;
                }

                // Extract rp_id from directory name
                let rp_id = path.file_name().and_then(|s| s.to_str())?.to_string();
                Some((rp_id, path))
            })
            .collect();

        debug!("Found {} RP directories", rp_dirs.len());

        // Process all credential files and build indexes functionally
        let indexes = rp_dirs.into_iter().fold(
            CredentialIndexes::default(),
            |mut indexes, (rp_id, rp_path)| {
                debug!("Scanning RP directory: {} ({:?})", rp_id, rp_path);

                // Read all .gpg files in this RP directory
                let gpg_files = match std::fs::read_dir(&rp_path) {
                    Ok(entries) => entries
                        .filter_map(|entry| entry.ok())
                        .filter_map(|entry| {
                            let path = entry.path();
                            // Only process .gpg files
                            if path.extension().and_then(|s| s.to_str()) == Some("gpg") {
                                Some(path)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>(),
                    Err(_) => Vec::new(),
                };

                // Process each credential file
                for cred_path in gpg_files {
                    // Extract credential ID from filename (no decryption!)
                    let filename = match cred_path.file_name().and_then(|s| s.to_str()) {
                        Some(name) => name,
                        None => continue,
                    };

                    if let Some(cred_id) = Self::parse_cred_id_from_filename(filename) {
                        debug!(
                            "Found credential file: {:?} (ID: {:02x?}...)",
                            cred_path,
                            &cred_id[..cred_id.len().min(8)]
                        );

                        // Index by credential ID
                        indexes.id.insert(cred_id.clone(), cred_path.clone());

                        // Index by RP ID
                        indexes
                            .rp
                            .entry(rp_id.clone())
                            .or_default()
                            .push(cred_path.clone());

                        // Index by RP hash (SHA-256 of RP ID)
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(rp_id.as_bytes());
                        let rp_hash: [u8; 32] = hasher.finalize().into();
                        indexes
                            .rp_hash
                            .entry(rp_hash)
                            .or_default()
                            .push(cred_path.clone());

                        debug!("Indexed credential for RP: {}", rp_id);
                    } else {
                        debug!(
                            "Skipping file with invalid credential ID format: {:?}",
                            cred_path
                        );
                    }
                }

                indexes
            },
        );

        debug!("Loaded {} credentials into indexes", indexes.id.len());

        Ok(indexes)
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
        self.evict_expired_cache_entries();

        // If cache is full, evict oldest entry
        if self.cache.len() >= MAX_CACHE_SIZE
            && let Some(oldest_path) = self.find_oldest_cache_entry()
        {
            debug!("Cache full - evicting oldest entry: {:?}", oldest_path);
            self.cache.remove(&oldest_path);
        }

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

        // Cache the decrypted credential with expiry time
        let cached = CachedCredential {
            credential: credential.clone(),
            expires_at: Instant::now() + CREDENTIAL_CACHE_TTL,
        };
        self.cache.insert(path.to_path_buf(), cached);
        debug!(
            "Cached credential (expires in {}s)",
            CREDENTIAL_CACHE_TTL.as_secs()
        );

        Ok(credential)
    }

    /// Evict all expired cache entries
    /// Evict all expired cache entries
    ///
    /// Called at the start of every mutable operation to ensure expired credentials
    /// are removed from memory promptly, even when no reads are occurring.
    fn evict_expired_cache_entries(&mut self) {
        let now = Instant::now();
        self.cache.retain(|path, cached| {
            let keep = now < cached.expires_at;
            if !keep {
                debug!("Evicting expired cache entry: {:?}", path);
            }
            keep
        });
    }

    /// Find the oldest cache entry (by expiry time)
    fn find_oldest_cache_entry(&self) -> Option<PathBuf> {
        self.cache
            .iter()
            .min_by_key(|(_, cached)| cached.expires_at)
            .map(|(path, _)| path.clone())
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
        self.evict_expired_cache_entries();

        let path = self.get_credential_path(&cred.rp.id, &cred.id);
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

        // Update all indexes
        self.indexes.id.insert(cred.id.to_vec(), path.clone());

        self.indexes
            .rp
            .entry(cred.rp.id.clone())
            .or_default()
            .push(path.clone());

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(cred.rp.id.as_bytes());
        let rp_hash: [u8; 32] = hasher.finalize().into();
        self.indexes.rp_hash.entry(rp_hash).or_default().push(path);

        Ok(())
    }

    /// Delete a credential from the store
    fn delete_credential(&mut self, id: &[u8]) -> Result<()> {
        self.evict_expired_cache_entries();

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

        // Remove from all indexes
        self.indexes.id.remove(id);

        // Remove from RP index
        if let Some(paths) = self.indexes.rp.get_mut(&cred.rp.id) {
            paths.retain(|p| p != &path);
            if paths.is_empty() {
                self.indexes.rp.remove(&cred.rp.id);
            }
        }

        // Remove from RP hash index
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(cred.rp.id.as_bytes());
        let rp_hash: [u8; 32] = hasher.finalize().into();
        if let Some(paths) = self.indexes.rp_hash.get_mut(&rp_hash) {
            paths.retain(|p| p != &path);
            if paths.is_empty() {
                self.indexes.rp_hash.remove(&rp_hash);
            }
        }

        debug!("Successfully deleted credential");

        Ok(())
    }

    /// Load all credentials from the store (non-caching version)
    /// Used for operations that need &self
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

/// Type alias for the three indexes returned by load_credential_paths
#[derive(Default)]
struct CredentialIndexes {
    id: HashMap<Vec<u8>, PathBuf>,
    rp: HashMap<String, Vec<PathBuf>>,
    rp_hash: HashMap<[u8; 32], Vec<PathBuf>>,
}

impl CredentialStorage for PassStorageAdapter {
    fn read_first(&mut self, filter: CredentialFilter) -> keylib::Result<Credential> {
        self.evict_expired_cache_entries();

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

    fn read_next(&mut self) -> keylib::Result<Credential> {
        self.evict_expired_cache_entries();

        debug!("read_next called");
        self.find_next().map_err(Into::into)
    }

    fn read(&mut self, id: &str, _rp: &str) -> keylib::Result<Vec<u8>> {
        self.evict_expired_cache_entries();

        debug!("read called with id: {}", id);

        let id_bytes = id.as_bytes();
        let cred = self.read_credential_by_id(id_bytes).map_err(|e| {
            debug!("Failed to read credential: {:?}", e);
            e
        })?;

        cred.to_bytes()
    }

    fn write(&mut self, _id: &str, _rp: &str, cred_ref: CredentialRef) -> keylib::Result<()> {
        self.evict_expired_cache_entries();

        debug!("write called for RP: {}", cred_ref.rp_id);

        let mut credential = cred_ref.to_owned();
        credential.sign_count = 0;
        credential.created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        credential.discoverable = true;

        let cred_json = serde_json::to_string(&credential).map_err(|e| {
            debug!("Failed to serialize credential: {:?}", e);
            Error::Storage(format!("Failed to serialize credential: {:?}", e))
        })?;
        self.write_credential(&credential, &cred_json)
            .map_err(Into::into)
    }

    fn delete(&mut self, id: &str) -> keylib::Result<()> {
        self.evict_expired_cache_entries();

        debug!("delete called with id: {}", id);
        let id_bytes = id.as_bytes();
        self.delete_credential(id_bytes).map_err(Into::into)
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

    fn get_relying_parties(&self) -> keylib::Result<Vec<RelyingParty>> {
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
        self.evict_expired_cache_entries();
    }
}
