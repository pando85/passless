//! Shared indexing and caching for credential storage backends

use soft_fido2::Credential;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use log::debug;
use sha2::{Digest, Sha256};

/// 30s TTL: short enough to minimize exposure, long enough for single auth flow
pub const CREDENTIAL_CACHE_TTL: Duration = Duration::from_secs(30);
pub const MAX_CACHE_SIZE: usize = 10;

/// Represents the structured path of a credential file
/// Path structure: {base_dir}/{rp_id}/{cred_id_hex}.{extension}
/// This allows extracting RP ID and cred ID without loading the file
#[derive(Debug, Clone)]
pub struct CredentialPathInfo {
    /// Relying Party ID (extracted from directory name)
    pub rp_id: String,
    /// Credential ID (decoded from filename)
    pub cred_id: Vec<u8>,
    /// File extension (e.g., "bin", "gpg", "tpm")
    pub extension: String,
}

impl CredentialPathInfo {
    /// Create from path components
    pub fn new(rp_id: String, cred_id: Vec<u8>, extension: String) -> Self {
        Self {
            rp_id,
            cred_id,
            extension,
        }
    }

    /// Parse from a file path
    /// Expects structure: {base_dir}/{rp_id}/{cred_id_hex}.{extension}
    pub fn from_path(path: &Path, extension: &str) -> Option<Self> {
        // Get filename and parse cred_id
        let filename = path.file_name()?.to_str()?;
        let cred_id = parse_cred_id_from_filename(filename, extension)?;

        // Get rp_id from parent directory name
        let parent = path.parent()?;
        let rp_id = parent.file_name()?.to_str()?.to_string();

        Some(Self {
            rp_id,
            cred_id,
            extension: extension.to_string(),
        })
    }

    /// Reconstruct the full path for this credential
    pub fn to_path(&self, base_dir: &Path) -> PathBuf {
        get_credential_path(base_dir, &self.rp_id, &self.cred_id, &self.extension)
    }

    /// Get the RP ID hash for this credential
    pub fn rp_id_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.rp_id.as_bytes());
        hasher.finalize().into()
    }
}

#[derive(Default)]
pub struct CredentialIndexes {
    /// Map credential ID to path info
    pub id: HashMap<Vec<u8>, CredentialPathInfo>,
    /// Map RP ID to list of credential IDs
    pub rp: HashMap<String, Vec<Vec<u8>>>,
    /// Map RP ID hash to list of credential IDs
    pub rp_hash: HashMap<[u8; 32], Vec<Vec<u8>>>,
}

pub struct CachedCredential {
    pub credential: Credential,
    pub expires_at: Instant,
}

pub struct CredentialCache {
    cache: HashMap<PathBuf, CachedCredential>,
}

impl CredentialCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    pub fn get(&self, path: &Path) -> Option<&CachedCredential> {
        self.cache.get(path)
    }

    pub fn insert(&mut self, path: PathBuf, credential: Credential) {
        let cached = CachedCredential {
            credential,
            expires_at: Instant::now() + CREDENTIAL_CACHE_TTL,
        };
        self.cache.insert(path, cached);
        debug!(
            "Cached credential (expires in {}s)",
            CREDENTIAL_CACHE_TTL.as_secs()
        );
    }

    pub fn remove(&mut self, path: &Path) {
        self.cache.remove(path);
    }

    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.cache.retain(|path, cached| {
            let keep = now < cached.expires_at;
            if !keep {
                debug!("Evicting expired cache entry: {:?}", path);
            }
            keep
        });
    }

    fn find_oldest(&self) -> Option<PathBuf> {
        self.cache
            .iter()
            .min_by_key(|(_, cached)| cached.expires_at)
            .map(|(path, _)| path.clone())
    }

    pub fn evict_oldest_if_full(&mut self) {
        if self.cache.len() >= MAX_CACHE_SIZE
            && let Some(oldest) = self.find_oldest()
        {
            debug!("Cache full - evicting oldest entry: {:?}", oldest);
            self.cache.remove(&oldest);
        }
    }
}

impl Default for CredentialCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_filename(cred_id: &[u8], extension: &str) -> String {
    let cred_id_hex: String = cred_id.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}.{}", cred_id_hex, extension)
}

pub fn parse_cred_id_from_filename(filename: &str, extension: &str) -> Option<Vec<u8>> {
    let name = filename.strip_suffix(&format!(".{}", extension))?;
    if name.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::with_capacity(name.len() / 2);
    for i in (0..name.len()).step_by(2) {
        let byte = u8::from_str_radix(&name[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

pub fn get_credential_path(
    storage_dir: &Path,
    rp_id: &str,
    cred_id: &[u8],
    extension: &str,
) -> PathBuf {
    storage_dir
        .join(rp_id)
        .join(get_filename(cred_id, extension))
}

/// Build indexes from directory structure - no credential loading needed!
/// Extracts RP ID and cred ID directly from the file path structure
pub fn load_credential_paths(
    storage_dir: &Path,
    extension: &str,
) -> std::io::Result<CredentialIndexes> {
    debug!("Loading credential paths (extension: {})", extension);

    let entries = match std::fs::read_dir(storage_dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!("Failed to read storage directory: {}", e);
            return Ok(CredentialIndexes::default());
        }
    };

    let rp_dirs: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_dir()
                || path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.starts_with('.'))
            {
                return None;
            }
            Some(path)
        })
        .collect();

    debug!("Found {} RP directories", rp_dirs.len());

    let mut indexes = CredentialIndexes::default();

    for rp_dir in rp_dirs {
        let cred_files = match std::fs::read_dir(&rp_dir) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some(extension) {
                        Some(path)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };

        for cred_path in cred_files {
            // Parse path info from the file path structure
            if let Some(path_info) = CredentialPathInfo::from_path(&cred_path, extension) {
                let cred_id = path_info.cred_id.clone();
                let rp_id = path_info.rp_id.clone();
                let rp_hash = path_info.rp_id_hash();

                // Index by credential ID
                indexes.id.insert(cred_id.clone(), path_info);

                // Index by RP ID
                indexes.rp.entry(rp_id).or_default().push(cred_id.clone());

                // Index by RP ID hash
                indexes.rp_hash.entry(rp_hash).or_default().push(cred_id);
            }
        }
    }

    debug!("Loaded {} credentials into indexes", indexes.id.len());
    Ok(indexes)
}

pub fn update_indexes_on_write(indexes: &mut CredentialIndexes, path_info: CredentialPathInfo) {
    let cred_id = path_info.cred_id.clone();
    let rp_id = path_info.rp_id.clone();
    let rp_hash = path_info.rp_id_hash();

    // Index by credential ID
    indexes.id.insert(cred_id.clone(), path_info);

    // Index by RP ID
    indexes.rp.entry(rp_id).or_default().push(cred_id.clone());

    // Index by RP ID hash
    indexes.rp_hash.entry(rp_hash).or_default().push(cred_id);
}

pub fn update_indexes_on_delete(indexes: &mut CredentialIndexes, cred_id: &[u8]) {
    // Get the path info to extract RP ID
    if let Some(path_info) = indexes.id.remove(cred_id) {
        let rp_id = &path_info.rp_id;
        let rp_hash = path_info.rp_id_hash();

        // Remove from RP index
        if let Some(cred_ids) = indexes.rp.get_mut(rp_id) {
            cred_ids.retain(|id| id != cred_id);
            if cred_ids.is_empty() {
                indexes.rp.remove(rp_id);
            }
        }

        // Remove from RP hash index
        if let Some(cred_ids) = indexes.rp_hash.get_mut(&rp_hash) {
            cred_ids.retain(|id| id != cred_id);
            if cred_ids.is_empty() {
                indexes.rp_hash.remove(&rp_hash);
            }
        }
    }
}
