//! Pass (password-store) storage adapter

pub mod gpg_id;
pub mod init;

use crate::storage::credential::Credential;
use crate::storage::index::{
    CredentialCache, CredentialIndexes, CredentialPathInfo, get_credential_path,
    load_credential_paths, update_indexes_on_delete, update_indexes_on_write,
};
use crate::storage::rp_id::validate_rp_id_for_storage;
use crate::storage::{CredentialFilter, CredentialStorage};
use crate::util::{bytes_to_hex, create_secure_dir_all};
use passless_core::error::{Error, Result};

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::time::Instant;

use core::fmt;
use log::{debug, error, info, warn};
use prs_lib::crypto::IsContext;
use prs_lib::{Ciphertext, Plaintext, Store};
use zeroize::Zeroizing;

/// Pass (password-store) storage adapter
///
/// Stores credentials as GPG-encrypted files in a password store directory.
/// Uses prs-lib for password store operations.
pub struct PassStorageAdapter {
    store_path: PathBuf,
    path: PathBuf,
    gpg_backend: GpgBackend,
    indexes: CredentialIndexes,
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
            _ => Err(Error::Config(format!(
                "Invalid GPG backend: '{}'. Must be 'gpgme' or 'gnupg-bin'",
                s
            ))),
        }
    }

    #[allow(dead_code)]
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Gpgme => {
                debug!("Validating GPGME backend configuration");
                Ok(())
            }
            Self::GnupgBin => {
                debug!("Validating GnuPG binary backend configuration");
                use std::process::Command;
                let result = Command::new("gpg").arg("--version").output();

                match result {
                    Ok(output) if output.status.success() => {
                        debug!(
                            "GPG binary is available: {:?}",
                            String::from_utf8_lossy(&output.stdout)
                        );
                        Ok(())
                    }
                    _ => {
                        warn!("GPG binary not found or not executable");
                        Ok(()) // Don't fail, just warn
                    }
                }
            }
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
    pub fn new_with_options(
        store_path: PathBuf,
        path: PathBuf,
        gpg_backend: GpgBackend,
        allow_create_without_prompt: bool,
    ) -> Result<Self> {
        let allow_create_without_prompt = cfg!(debug_assertions) && allow_create_without_prompt;
        info!("Using pass (password-store) backend");
        info!("Store path: {}", store_path.display());
        info!("Path: {}", path.display());
        info!("GPG backend: {}", gpg_backend);

        debug!("Opening password store at: {:?}", store_path);

        // Ensure the password store is initialized
        // This will prompt the user via notifications if not initialized
        self::init::ensure_initialized(&store_path, gpg_backend, allow_create_without_prompt)?;

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

    /// Read a credential from a specific file path
    /// Uses time-limited cache to avoid redundant GPG decryption
    fn read_credential_from_path(&mut self, path: &Path) -> Result<soft_fido2::Credential> {
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
            error!("Failed to decrypt credential: {:?}", e);
            Error::Storage(format!("Failed to decrypt credential: {:?}", e))
        })?;

        debug!("Successfully decrypted credential");

        // Parse credential from decrypted bytes
        let credential: soft_fido2::Credential = Credential::from_bytes(plaintext.unsecure_ref())
            .map(|cred| cred.to_soft_fido2())
            .map_err(|e| Error::Storage(format!("Failed to parse credential: {:?}", e)))?;

        // Cache the decrypted credential with automatic TTL
        self.cache.insert(path.to_path_buf(), credential.clone());

        Ok(credential)
    }

    /// Read a credential by its ID
    fn read_credential_by_id(&mut self, id: &[u8]) -> Result<soft_fido2::Credential> {
        let path_info = self.indexes.id.get(id).ok_or_else(|| {
            debug!("Credential not found in index");
            Error::Storage("Credential not found".to_string())
        })?;

        let path = path_info.to_path(&self.get_fido2_path());
        self.read_credential_from_path(&path)
    }

    /// Find the nearest `.gpg-id` file by walking from `target`'s parent
    /// directory up to `store_root`. Returns the path and raw content.
    fn find_nearest_gpg_id(&self, target: &Path) -> Result<(PathBuf, String)> {
        gpg_id::find_nearest_gpg_id(&self.store_path, target)
    }

    /// Resolve GPG recipients for a target file using hierarchical .gpg-id lookup.
    fn resolve_recipients_for_target(&self, target: &Path) -> Result<prs_lib::Recipients> {
        gpg_id::resolve_recipients_for_target(&self.store_path, target)
    }

    /// Parse GPG key IDs from .gpg-id file content.
    #[allow(dead_code)]
    fn parse_gpg_id_content(
        &self,
        content: &str,
        gpg_id_path: &Path,
    ) -> Result<prs_lib::Recipients> {
        gpg_id::parse_gpg_id_content(content, gpg_id_path)
    }

    /// Write a credential to the store
    fn write_credential_bytes(
        &mut self,
        cred: &soft_fido2::Credential,
        cred_bytes: &[u8],
    ) -> Result<()> {
        self.cache.evict_expired();

        let rp_id = validate_rp_id_for_storage(cred.rp.id.as_str())
            .map_err(|e| Error::Storage(format!("Invalid RP ID: {}", e)))?;

        let path = get_credential_path(&self.get_fido2_path(), &rp_id, &cred.id, "gpg");
        debug!("Writing credential to: {:?}", path);

        // Ensure parent directory exists with secure permissions
        if let Some(parent) = path.parent() {
            create_secure_dir_all(parent).map_err(|e| {
                debug!("Failed to create directory: {}", e);
                Error::Storage(format!("Failed to create directory: {}", e))
            })?;
        }

        // Resolve recipients by walking up from target to find the nearest .gpg-id
        let recipients = self.resolve_recipients_for_target(&path)?;

        // Create crypto context
        let mut context = self.create_crypto_context()?;

        // Encrypt and write the credential data directly to file
        let plaintext = Plaintext::from(cred_bytes.to_vec());

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
        let path_info = CredentialPathInfo::new(rp_id, cred.id.to_vec(), "gpg".to_string());
        update_indexes_on_write(&mut self.indexes, path_info);

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

        debug!("Deleting credential with ID: {}", bytes_to_hex(id));

        let path_info = self
            .indexes
            .id
            .get(id)
            .ok_or_else(|| {
                debug!("Credential not found in index");
                Error::Storage("Credential not found".to_string())
            })?
            .clone();

        // Convert to actual path
        let path = path_info.to_path(&self.get_fido2_path());

        // Delete the file
        std::fs::remove_file(&path).map_err(|e| {
            debug!("Failed to delete file: {}", e);
            Error::Storage(format!("Failed to delete file: {}", e))
        })?;

        // Remove from cache
        self.cache.remove(&path);

        // Remove from all indexes using shared function
        update_indexes_on_delete(&mut self.indexes, id);

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

    /// Find the next credential matching the current filter
    /// Uses indexes for efficient lookup
    fn find_next(&mut self) -> Result<soft_fido2::Credential> {
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

    // ── Audit / re-encrypt ──────────────────────────────────────────────────

    /// Scan all passkey files and report those whose OpenPGP packet recipients
    /// differ from the effective `.gpg-id` policy.
    ///
    /// Requires the `gpg` binary for packet inspection.
    #[allow(dead_code)]
    pub fn audit_passkey_recipients(&self) -> Result<Vec<AuditEntry>> {
        let fido2_path = self.get_fido2_path();
        let indexes = load_credential_paths(&fido2_path, "gpg")
            .map_err(|e| Error::Storage(format!("Failed to scan credentials: {}", e)))?;

        let mut entries = Vec::new();

        for path_info in indexes.id.values() {
            let path = path_info.to_path(&fido2_path);
            if !path.exists() {
                continue;
            }

            let actual = match extract_gpg_key_ids(&path) {
                Ok(ids) => ids,
                Err(e) => {
                    entries.push(AuditEntry {
                        path,
                        expected_recipients: vec![],
                        actual_recipients: vec![],
                        match_result: RecipientMatch::InspectionError(e.to_string()),
                    });
                    continue;
                }
            };

            let expected = match self.find_nearest_gpg_id(&path) {
                Ok((_, content)) => gpg_id::parse_raw_key_ids(&content),
                Err(e) => {
                    entries.push(AuditEntry {
                        path,
                        expected_recipients: vec![],
                        actual_recipients: actual.clone(),
                        match_result: RecipientMatch::ResolutionError(e.to_string()),
                    });
                    continue;
                }
            };

            let match_result = if actual == expected {
                RecipientMatch::Match
            } else {
                RecipientMatch::Mismatch
            };

            entries.push(AuditEntry {
                path,
                expected_recipients: expected,
                actual_recipients: actual,
                match_result,
            });
        }

        Ok(entries)
    }

    /// Re-encrypt a passkey file so its OpenPGP recipients match the current
    /// `.gpg-id` policy.
    ///
    /// 1. Decrypts the file using an available secret key.
    /// 2. Resolves the effective recipients via `resolve_recipients_for_target`.
    /// 3. Re-encrypts to a temporary file.
    /// 4. Atomically renames the temporary over the original.
    /// 5. Commits the change via the password-store Git integration.
    #[allow(dead_code)]
    pub fn reencrypt_passkey_file(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::Storage(format!(
                "File does not exist: {}",
                path.display()
            )));
        }

        let encrypted_data = std::fs::read(path).map_err(|e| {
            Error::Storage(format!("Failed to read file {}: {}", path.display(), e))
        })?;

        let mut context = self.create_crypto_context()?;

        let ciphertext = Ciphertext::from(encrypted_data);
        let plaintext = context.decrypt(ciphertext).map_err(|e| {
            Error::Storage(format!(
                "Failed to decrypt {} for re-encryption: {:?}",
                path.display(),
                e
            ))
        })?;

        let recipients = self.resolve_recipients_for_target(path)?;

        let parent = path
            .parent()
            .ok_or_else(|| Error::Storage(format!("No parent directory for {}", path.display())))?;

        let tmp_name = format!(
            ".reencrypt.{}.{}",
            std::process::id(),
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("credential.gpg")
        );
        let tmp_path = parent.join(&tmp_name);

        context
            .encrypt_file(&recipients, plaintext, &tmp_path)
            .map_err(|e| {
                Error::Storage(format!(
                    "Failed to re-encrypt credential {}: {:?}",
                    path.display(),
                    e
                ))
            })?;

        std::fs::rename(&tmp_path, path).map_err(|e| {
            Error::Storage(format!(
                "Failed to replace {} with re-encrypted version: {}",
                path.display(),
                e
            ))
        })?;

        let relative_path = path
            .strip_prefix(&self.store_path)
            .unwrap_or(path)
            .display();
        let message = format!(
            "Re-encrypt {} with current .gpg-id recipient policy.",
            relative_path
        );
        self.sync_finalize(&message)?;

        info!("Re-encrypted {}", path.display());
        Ok(())
    }
}

/// Extract GPG public-key-encrypted session key IDs from an OpenPGP file by
/// running `gpg --list-packets --verbose`.
#[allow(dead_code)]
fn extract_gpg_key_ids(path: &Path) -> Result<Vec<String>> {
    let output = std::process::Command::new("gpg")
        .args(["--batch", "--no-tty", "--list-packets", "--verbose"])
        .arg(path)
        .output()
        .map_err(|e| {
            Error::Storage(format!(
                "Failed to run gpg --list-packets on {}: {}",
                path.display(),
                e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Storage(format!(
            "gpg --list-packets failed for {}: {}",
            path.display(),
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut key_ids: Vec<String> = Vec::new();

    for line in stdout.lines() {
        if line.contains("pubkey enc packet")
            && let Some(after_keyid) = line.split("keyid ").nth(1)
        {
            let kid = after_keyid
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !kid.is_empty() && !key_ids.contains(&kid) {
                key_ids.push(kid);
            }
        }
    }

    Ok(key_ids)
}

/// Result of comparing expected vs actual recipients for a single credential file.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientMatch {
    /// The credential's OpenPGP recipients match the .gpg-id policy.
    Match,
    /// The credential's recipients differ from the .gpg-id policy.
    Mismatch,
    /// The expected recipients could not be resolved.
    ResolutionError(String),
    /// The actual recipients could not be inspected.
    InspectionError(String),
}

/// An audit entry describing the recipient match status for one credential file.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Path to the credential file.
    pub path: PathBuf,
    /// Expected recipient key IDs (16-char uppercase hex).
    pub expected_recipients: Vec<String>,
    /// Actual recipient key IDs extracted from the OpenPGP packets.
    pub actual_recipients: Vec<String>,
    /// Whether the expected and actual recipients match.
    pub match_result: RecipientMatch,
}

impl CredentialStorage for PassStorageAdapter {
    fn read_first(
        &mut self,
        filter: CredentialFilter,
    ) -> soft_fido2::Result<soft_fido2::Credential> {
        self.cache.evict_expired();

        debug!("read_first called with filter: {:?}", filter);

        self.iteration_entries = self.indexes.resolve_filter(&filter, &self.get_fido2_path());
        self.iteration_index = 0;

        debug!(
            "Starting iteration with {} entries for filter: {:?}",
            self.iteration_entries.len(),
            filter
        );

        self.find_next().map_err(Into::into)
    }

    fn read_next(&mut self) -> soft_fido2::Result<soft_fido2::Credential> {
        self.cache.evict_expired();

        debug!("read_next called");
        self.find_next().map_err(Into::into)
    }

    fn read(&mut self, id: &[u8]) -> soft_fido2::Result<soft_fido2::Credential> {
        self.cache.evict_expired();

        debug!("read called with id: {}", bytes_to_hex(id));

        // Load and return credential directly (no re-serialization)
        self.read_credential_by_id(id).map_err(Into::into)
    }

    fn write(&mut self, cred_ref: soft_fido2::CredentialRef) -> soft_fido2::Result<()> {
        self.cache.evict_expired();

        debug!("write called for RP: {}", cred_ref.rp_id);

        let credential = cred_ref.to_owned();
        // Convert to our format for controlled serialization
        let our_cred = Credential::from_soft_fido2(&credential);
        // Use Zeroizing to ensure credential bytes are cleared from memory after use
        let cred_bytes = Zeroizing::new(our_cred.to_bytes().map_err(|e| {
            debug!("Failed to serialize credential: {:?}", e);
            Error::Storage(format!("Failed to serialize credential: {:?}", e))
        })?);
        self.write_credential_bytes(&credential, &cred_bytes)
            .map_err(Into::into)
    }

    fn delete(&mut self, id: &[u8]) -> soft_fido2::Result<()> {
        self.cache.evict_expired();

        debug!("delete called with id: {}", bytes_to_hex(id));
        self.delete_credential(id).map_err(Into::into)
    }

    fn count_credentials(&self) -> usize {
        let count = self.indexes.id.len();
        debug!("count_credentials: {}", count);
        count
    }

    fn disable_user_verification(&self) -> bool {
        // Pass backend doesn't support user verification
        true
    }

    fn cleanup_expired_cache(&mut self) {
        self.cache.evict_expired();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    fn write_gpg_id(dir: &Path, content: &str) {
        fs::write(dir.join(".gpg-id"), content).unwrap();
    }

    fn create_adapter(store_root: &Path) -> PassStorageAdapter {
        PassStorageAdapter {
            store_path: store_root.to_path_buf(),
            path: PathBuf::from("fido2"),
            gpg_backend: GpgBackend::GnupgBin,
            indexes: CredentialIndexes::default(),
            cache: CredentialCache::new(),
            iteration_index: 0,
            iteration_entries: vec![],
        }
    }

    // ── parse_gpg_id_content ─────────────────────────────────────────────

    #[test]
    fn test_parse_single_key_id() {
        let adapter = create_adapter(Path::new("/tmp/test"));
        let dir = Path::new("/tmp/test");
        let content = "ABCDEF0123456789ABCDEF0123456789ABCDEF01\n";
        let result = adapter.parse_gpg_id_content(content, &dir.join(".gpg-id"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_skips_comments_and_blanks() {
        let adapter = create_adapter(Path::new("/tmp/test"));
        let dir = Path::new("/tmp/test");
        let content = "# comment\n\nABCDEF0123456789ABCDEF0123456789ABCDEF01\n  \n";
        let result = adapter.parse_gpg_id_content(content, &dir.join(".gpg-id"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_rejects_short_key_id() {
        let adapter = create_adapter(Path::new("/tmp/test"));
        let dir = Path::new("/tmp/test");
        let content = "DEADBEEF\n";
        let result = adapter.parse_gpg_id_content(content, &dir.join(".gpg-id"));
        assert!(result.is_err(), "short 8-char key ID should be rejected");
        let err = match result {
            Err(e) => e.to_string(),
            _ => unreachable!(),
        };
        assert!(
            err.contains("8-character"),
            "error should mention 8-char: {}",
            err
        );
    }

    #[test]
    fn test_parse_strips_subkey_marker() {
        let adapter = create_adapter(Path::new("/tmp/test"));
        let dir = Path::new("/tmp/test");
        let content = "ABCDEF0123456789ABCDEF0123456789ABCDEF01!\n";
        let result = adapter.parse_gpg_id_content(content, &dir.join(".gpg-id"));
        assert!(
            result.is_ok(),
            "key ID with ! subkey marker should be accepted"
        );
    }

    #[test]
    fn test_parse_multiple_recipients() {
        let adapter = create_adapter(Path::new("/tmp/test"));
        let dir = Path::new("/tmp/test");
        let content =
            "ABCDEF0123456789ABCDEF0123456789ABCDEF01\n1234567890ABCDEF1234567890ABCDEF12345678\n";
        let result = adapter.parse_gpg_id_content(content, &dir.join(".gpg-id"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_empty_content_fails() {
        let adapter = create_adapter(Path::new("/tmp/test"));
        let dir = Path::new("/tmp/test");
        let result = adapter.parse_gpg_id_content("", &dir.join(".gpg-id"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_only_comments_fails() {
        let adapter = create_adapter(Path::new("/tmp/test"));
        let dir = Path::new("/tmp/test");
        let result = adapter.parse_gpg_id_content("# only a comment\n", &dir.join(".gpg-id"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_non_hex_chars_skipped() {
        let adapter = create_adapter(Path::new("/tmp/test"));
        let dir = Path::new("/tmp/test");
        let content = "NOTHEX!!\nABCDEF0123456789ABCDEF0123456789ABCDEF01\n";
        let result = adapter.parse_gpg_id_content(content, &dir.join(".gpg-id"));
        assert!(
            result.is_ok(),
            "non-hex lines should be skipped, valid keys should remain"
        );
    }

    #[test]
    fn test_parse_0x_prefix_stripped() {
        let adapter = create_adapter(Path::new("/tmp/test"));
        let dir = Path::new("/tmp/test");
        let content = "0xABCDEF0123456789ABCDEF0123456789ABCDEF01\n";
        let result = adapter.parse_gpg_id_content(content, &dir.join(".gpg-id"));
        assert!(result.is_ok(), "0x-prefixed key ID should be accepted");
    }

    // ── resolve_recipients_for_target ─────────────────────────────────────

    #[test]
    fn test_resolve_root_gpg_id() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let target = root.join("fido2/example.com/cred.gpg");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        write_gpg_id(&root, "ABCDEF0123456789ABCDEF0123456789ABCDEF01\n");

        let adapter = create_adapter(&root);
        let result = adapter.resolve_recipients_for_target(&target);
        assert!(
            result.is_ok(),
            "should find root .gpg-id: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_resolve_hierarchical_fido2_overrides_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let fido2_dir = root.join("fido2");
        let target = fido2_dir.join("example.com/cred.gpg");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        write_gpg_id(&root, "0000000000000000000000000000000000000001\n");
        write_gpg_id(&fido2_dir, "0000000000000000000000000000000000000002\n");

        let adapter = create_adapter(&root);
        let result = adapter.resolve_recipients_for_target(&target);
        assert!(
            result.is_ok(),
            "should find fido2/.gpg-id: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_resolve_hierarchical_rp_dir_overrides_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let fido2_dir = root.join("fido2");
        let rp_dir = fido2_dir.join("example.com");
        let target = rp_dir.join("cred.gpg");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        write_gpg_id(&root, "0000000000000000000000000000000000000001\n");
        write_gpg_id(&fido2_dir, "0000000000000000000000000000000000000002\n");
        write_gpg_id(&rp_dir, "0000000000000000000000000000000000000003\n");

        let adapter = create_adapter(&root);
        let result = adapter.resolve_recipients_for_target(&target);
        assert!(
            result.is_ok(),
            "should find example.com/.gpg-id: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_resolve_target_outside_store_fails() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        fs::create_dir_all(&root).unwrap();

        let outside = dir.path().join("outside/cred.gpg");
        let adapter = create_adapter(&root);
        let result = adapter.resolve_recipients_for_target(&outside);
        assert!(result.is_err(), "target outside store should fail");
        let err = match result {
            Err(e) => e.to_string(),
            _ => unreachable!(),
        };
        assert!(err.contains("not within store root"));
    }

    #[test]
    fn test_resolve_missing_gpg_id_fails() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let target = root.join("fido2/example.com/cred.gpg");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        let adapter = create_adapter(&root);
        let result = adapter.resolve_recipients_for_target(&target);
        assert!(result.is_err(), "missing .gpg-id should fail");
    }

    #[test]
    fn test_resolve_empty_gpg_id_fails() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let target = root.join("fido2/example.com/cred.gpg");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        write_gpg_id(&root, "# only a comment\n");

        let adapter = create_adapter(&root);
        let result = adapter.resolve_recipients_for_target(&target);
        assert!(result.is_err(), "empty .gpg-id (only comments) should fail");
    }

    #[test]
    fn test_resolve_short_key_id_in_root_fails() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let target = root.join("fido2/example.com/cred.gpg");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        write_gpg_id(&root, "DEADBEEF\n");

        let adapter = create_adapter(&root);
        let result = adapter.resolve_recipients_for_target(&target);
        assert!(
            result.is_err(),
            "short 8-char key ID in .gpg-id should fail"
        );
    }

    #[test]
    fn test_resolve_with_subkey_marker() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let target = root.join("fido2/example.com/cred.gpg");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        write_gpg_id(&root, "ABCDEF0123456789ABCDEF0123456789ABCDEF01!\n");

        let adapter = create_adapter(&root);
        let result = adapter.resolve_recipients_for_target(&target);
        assert!(result.is_ok(), "key IDs with ! marker should be accepted");
    }

    // ── find_nearest_gpg_id ───────────────────────────────────────────────

    #[test]
    fn test_find_nearest_gpg_id_root_only() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let target = root.join("fido2/example.com/cred.gpg");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        write_gpg_id(&root, "ABCDEF0123456789ABCDEF0123456789ABCDEF01\n");

        let adapter = create_adapter(&root);
        let (found_path, content) = adapter.find_nearest_gpg_id(&target).unwrap();
        assert_eq!(found_path, root.join(".gpg-id"));
        assert!(content.contains("ABCDEF"));
    }

    #[test]
    fn test_find_nearest_gpg_id_prefers_closest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let fido2_dir = root.join("fido2");
        let rp_dir = fido2_dir.join("example.com");
        let target = rp_dir.join("cred.gpg");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        write_gpg_id(&root, "ROOT00000000000000000000000000000000001\n");
        write_gpg_id(&rp_dir, "RP000000000000000000000000000000000003\n");

        let adapter = create_adapter(&root);
        let (found_path, _) = adapter.find_nearest_gpg_id(&target).unwrap();
        assert_eq!(found_path, rp_dir.join(".gpg-id"));
    }

    #[test]
    fn test_find_nearest_gpg_id_outside_store_fails() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        fs::create_dir_all(&root).unwrap();

        let outside = dir.path().join("outside/cred.gpg");
        let adapter = create_adapter(&root);
        let result = adapter.find_nearest_gpg_id(&outside);
        assert!(result.is_err());
    }
}
