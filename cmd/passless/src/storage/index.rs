use crate::storage::CredentialFilter;
use crate::storage::rp_id::ValidatedRpId;
use crate::util::bytes_to_hex;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use log::{debug, warn};
use sha2::{Digest, Sha256};

pub const CREDENTIAL_CACHE_TTL: Duration = Duration::from_secs(30);
pub const MAX_CACHE_SIZE: usize = 10;

#[derive(Debug, Clone)]
pub struct CredentialPathInfo {
    pub rp_id: ValidatedRpId,
    pub cred_id: Vec<u8>,
    pub extension: String,
}

impl CredentialPathInfo {
    pub fn new(rp_id: ValidatedRpId, cred_id: Vec<u8>, extension: String) -> Self {
        Self {
            rp_id,
            cred_id,
            extension,
        }
    }

    pub fn from_path(path: &Path, extension: &str) -> Option<Self> {
        let filename = path.file_name()?.to_str()?;
        let cred_id = parse_cred_id_from_filename(filename, extension)?;

        let parent = path.parent()?;
        let rp_id_str = parent.file_name()?.to_str()?;

        let rp_id = match ValidatedRpId::try_from(rp_id_str) {
            Ok(id) => id,
            Err(e) => {
                warn!(
                    "Skipping credential at {}: invalid RP ID directory name: {}",
                    path.display(),
                    e
                );
                return None;
            }
        };

        Some(Self {
            rp_id,
            cred_id,
            extension: extension.to_string(),
        })
    }

    pub fn to_path(&self, base_dir: &Path) -> PathBuf {
        get_credential_path(base_dir, &self.rp_id, &self.cred_id, &self.extension)
    }

    pub fn rp_id_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.rp_id.as_bytes());
        hasher.finalize().into()
    }
}

#[derive(Default)]
pub struct CredentialIndexes {
    pub id: HashMap<Vec<u8>, CredentialPathInfo>,
    pub rp: HashMap<String, Vec<Vec<u8>>>,
    pub rp_hash: HashMap<[u8; 32], Vec<Vec<u8>>>,
}

impl CredentialIndexes {
    pub fn resolve_filter(&self, filter: &CredentialFilter, base_dir: &Path) -> Vec<PathBuf> {
        match filter {
            CredentialFilter::None => self
                .id
                .values()
                .map(|path_info| path_info.to_path(base_dir))
                .collect(),
            CredentialFilter::ById(id) => {
                if let Some(path_info) = self.id.get(id) {
                    vec![path_info.to_path(base_dir)]
                } else {
                    Vec::new()
                }
            }
            CredentialFilter::ByRp(rp_id) => self
                .rp
                .get(rp_id)
                .map(|cred_ids| {
                    cred_ids
                        .iter()
                        .filter_map(|cred_id| {
                            self.id
                                .get(cred_id)
                                .map(|path_info| path_info.to_path(base_dir))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            CredentialFilter::ByHash(hash) => self
                .rp_hash
                .get(hash)
                .map(|cred_ids| {
                    cred_ids
                        .iter()
                        .filter_map(|cred_id| {
                            self.id
                                .get(cred_id)
                                .map(|path_info| path_info.to_path(base_dir))
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

pub struct CachedCredential {
    pub credential: soft_fido2::Credential,
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

    pub fn insert(&mut self, path: PathBuf, credential: soft_fido2::Credential) {
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
        if let Some(cached) = self.cache.remove(path) {
            drop(cached.credential);
        }
    }

    pub fn evict_expired(&mut self) {
        let now = Instant::now();

        let expired: Vec<PathBuf> = self
            .cache
            .iter()
            .filter(|(_, cached)| now >= cached.expires_at)
            .map(|(path, _)| path.clone())
            .collect();

        for path in expired {
            debug!("Evicting expired cache entry: {:?}", path);
            if let Some(cached) = self.cache.remove(&path) {
                drop(cached.credential);
            }
        }
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
            if let Some(cached) = self.cache.remove(&oldest) {
                drop(cached.credential);
            }
        }
    }
}

impl Default for CredentialCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_filename(cred_id: &[u8], extension: &str) -> String {
    format!("{}.{}", bytes_to_hex(cred_id), extension)
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
    rp_id: &ValidatedRpId,
    cred_id: &[u8],
    extension: &str,
) -> PathBuf {
    storage_dir
        .join(rp_id.as_str())
        .join(get_filename(cred_id, extension))
}

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
            if let Some(path_info) = CredentialPathInfo::from_path(&cred_path, extension) {
                let cred_id = path_info.cred_id.clone();
                let rp_id = path_info.rp_id.clone();
                let rp_hash = path_info.rp_id_hash();

                indexes.id.insert(cred_id.clone(), path_info);
                indexes
                    .rp
                    .entry(rp_id.to_string())
                    .or_default()
                    .push(cred_id.clone());
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

    let is_new = !indexes.id.contains_key(&cred_id);

    indexes.id.insert(cred_id.clone(), path_info);

    if is_new {
        indexes
            .rp
            .entry(rp_id.to_string())
            .or_default()
            .push(cred_id.clone());
        indexes.rp_hash.entry(rp_hash).or_default().push(cred_id);
    }
}

pub fn update_indexes_on_delete(indexes: &mut CredentialIndexes, cred_id: &[u8]) {
    if let Some(path_info) = indexes.id.remove(cred_id) {
        let rp_id_str = path_info.rp_id.to_string();
        let rp_hash = path_info.rp_id_hash();

        if let Some(cred_ids) = indexes.rp.get_mut(&rp_id_str) {
            cred_ids.retain(|id| id != cred_id);
            if cred_ids.is_empty() {
                indexes.rp.remove(&rp_id_str);
            }
        }

        if let Some(cred_ids) = indexes.rp_hash.get_mut(&rp_hash) {
            cred_ids.retain(|id| id != cred_id);
            if cred_ids.is_empty() {
                indexes.rp_hash.remove(&rp_hash);
            }
        }
    }
}
