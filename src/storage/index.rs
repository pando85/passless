//! Shared indexing and caching for credential storage backends

use keylib::Credential;
use log::debug;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// 30s TTL: short enough to minimize exposure, long enough for single auth flow
pub const CREDENTIAL_CACHE_TTL: Duration = Duration::from_secs(30);
pub const MAX_CACHE_SIZE: usize = 10;

#[derive(Default)]
pub struct CredentialIndexes {
    pub id: HashMap<Vec<u8>, PathBuf>,
    pub rp: HashMap<String, Vec<PathBuf>>,
    pub rp_hash: HashMap<[u8; 32], Vec<PathBuf>>,
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

/// Build indexes from directory structure - no decryption/unsealing needed
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

    let rp_dirs: Vec<(String, PathBuf)> = entries
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

            let rp_id = path.file_name().and_then(|s| s.to_str())?.to_string();
            Some((rp_id, path))
        })
        .collect();

    debug!("Found {} RP directories", rp_dirs.len());

    let indexes = rp_dirs.into_iter().fold(
        CredentialIndexes::default(),
        |mut indexes, (rp_id, rp_path)| {
            debug!("Scanning RP directory: {}", rp_id);

            let cred_files = match std::fs::read_dir(&rp_path) {
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
                let filename = match cred_path.file_name().and_then(|s| s.to_str()) {
                    Some(name) => name,
                    None => continue,
                };

                if let Some(cred_id) = parse_cred_id_from_filename(filename, extension) {
                    indexes.id.insert(cred_id.clone(), cred_path.clone());
                    indexes
                        .rp
                        .entry(rp_id.clone())
                        .or_default()
                        .push(cred_path.clone());

                    let mut hasher = Sha256::new();
                    hasher.update(rp_id.as_bytes());
                    let rp_hash: [u8; 32] = hasher.finalize().into();
                    indexes.rp_hash.entry(rp_hash).or_default().push(cred_path);
                }
            }

            indexes
        },
    );

    debug!("Loaded {} credentials into indexes", indexes.id.len());
    Ok(indexes)
}

pub fn update_indexes_on_write(
    indexes: &mut CredentialIndexes,
    path: PathBuf,
    cred_id: Vec<u8>,
    rp_id: String,
) {
    indexes.id.insert(cred_id, path.clone());
    indexes
        .rp
        .entry(rp_id.clone())
        .or_default()
        .push(path.clone());

    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    let rp_hash: [u8; 32] = hasher.finalize().into();
    indexes.rp_hash.entry(rp_hash).or_default().push(path);
}

pub fn update_indexes_on_delete(
    indexes: &mut CredentialIndexes,
    path: &Path,
    cred_id: &[u8],
    rp_id: &str,
) {
    indexes.id.remove(cred_id);

    if let Some(paths) = indexes.rp.get_mut(rp_id) {
        paths.retain(|p| p != path);
        if paths.is_empty() {
            indexes.rp.remove(rp_id);
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    let rp_hash: [u8; 32] = hasher.finalize().into();
    if let Some(paths) = indexes.rp_hash.get_mut(&rp_hash) {
        paths.retain(|p| p != path);
        if paths.is_empty() {
            indexes.rp_hash.remove(&rp_hash);
        }
    }
}
