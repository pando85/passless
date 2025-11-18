//! TPM (Trusted Platform Module) storage adapter
//!
//! This adapter implements the CredentialStorage trait using TPM 2.0 for secure credential storage.
//! Credentials are sealed using the TPM, ensuring they can only be unsealed on the same machine.
//!
//! The implementation uses:
//! - TPM2_CreatePrimary to create a primary storage key in the owner hierarchy
//! - TPM2_Create to seal the credential data under the primary key
//! - TPM2_Load and TPM2_Unseal to retrieve sealed credentials
//!
//! File structure: {storage_dir}/{rp_id}/{cred_id_hex}.tpm
//! Indexes are built by scanning directory structure (no unsealing needed)
//! Credentials are only unsealed when needed for authentication

use crate::storage::{CredentialFilter, CredentialStorage};

use keylib::credential::RelyingParty;
use keylib::{Credential, CredentialRef, Result};

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use log::{debug, info};
use rand::RngCore;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use tss_esapi::constants::SessionType;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy};
use tss_esapi::structures::{KeyedHashScheme, PublicKeyedHashParameters};
use tss_esapi::structures::{Public, PublicBuilder};
use tss_esapi::structures::{
    PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme, SymmetricDefinitionObject,
};
use tss_esapi::tss2_esys::{TPM2B_PRIVATE, TPM2B_PUBLIC};
use tss_esapi::{Context, Tcti};

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

/// TPM storage adapter
///
/// Stores credentials as TPM-sealed files in a directory structure.
/// File structure: {storage_dir}/{rp_id}/{cred_id_hex}.tpm
/// Uses indexes for efficient lookups without unsealing all credentials.
pub struct TpmStorageAdapter {
    storage_dir: PathBuf,
    indexes: CredentialIndexes,
    /// Time-limited cache: file_path -> (credential, expiry_time)
    cache: HashMap<PathBuf, CachedCredential>,
    iteration_index: usize,
    iteration_entries: Vec<PathBuf>,
    context: Mutex<Context>,
}

/// Indexes for efficient credential lookups
#[derive(Default)]
struct CredentialIndexes {
    /// Map credential ID to file path
    id: HashMap<Vec<u8>, PathBuf>,
    /// Map RP ID to list of credential file paths
    rp: HashMap<String, Vec<PathBuf>>,
    /// Map RP hash to list of credential file paths
    rp_hash: HashMap<[u8; 32], Vec<PathBuf>>,
}

/// Represents a sealed credential blob stored on disk
#[derive(serde::Serialize, serde::Deserialize)]
struct SealedBlob {
    /// The encrypted credential data (AES-GCM encrypted)
    encrypted_data: Vec<u8>,
    /// The nonce used for AES-GCM encryption (96 bits)
    nonce: Vec<u8>,
    /// The private part of the TPM-sealed encryption key
    tpm_private: Vec<u8>,
    /// The public part of the TPM-sealed encryption key
    tpm_public: Vec<u8>,
}

impl TpmStorageAdapter {
    /// Create a new TPM storage adapter
    pub fn new(storage_dir: PathBuf, tcti: Option<String>) -> Result<Self> {
        info!("Using TPM 2.0 backend");
        info!("Storage path: {}", storage_dir.display());
        fs::create_dir_all(&storage_dir).map_err(|e| {
            log::error!("Failed to create storage directory: {}", e);
            keylib::Error::Other
        })?;

        // Initialize TPM context
        let tcti_conf = if let Some(ref tcti_str) = tcti {
            info!("Using TCTI configuration: {}", tcti_str);
            Tcti::from_str(tcti_str).map_err(|e| {
                log::error!("Failed to parse TCTI configuration '{}': {}", tcti_str, e);
                log::error!("TCTI format examples:");
                log::error!("  - Hardware TPM: device:/dev/tpmrm0");
                log::error!("  - swtpm socket: swtpm:path=/path/to/socket");

                keylib::Error::Other
            })?
        } else {
            // Default TCTI (device or simulator)
            info!("Using default TCTI: device:/dev/tpmrm0");
            Tcti::Device(Default::default())
        };

        let mut context = Context::new(tcti_conf).map_err(|e| {
            log::error!("Failed to create TPM context: {}", e);
            if let Some(ref tcti_str) = tcti {
                log::error!("TCTI used: {}", tcti_str);
            } else {
                log::error!("TCTI used: device:/dev/tpmrm0 (default)");
            }
            log::error!("Troubleshooting steps:");
            log::error!("  1. Verify TPM device exists: ls -l /dev/tpm*");
            log::error!("  2. Check permissions on TPM device");
            keylib::Error::Other
        })?;

        // Start auth session for encryption
        let session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinitionObject::AES_128_CFB.into(),
                HashingAlgorithm::Sha256,
            )
            .map_err(|e| {
                log::error!("Failed to start TPM auth session: {}", e);
                keylib::Error::Other
            })?
            .ok_or_else(|| {
                log::error!("TPM auth session returned None");
                keylib::Error::Other
            })?;

        context.set_sessions((Some(session), None, None));

        info!("TPM context initialized successfully");

        let mut adapter = Self {
            storage_dir,
            indexes: Default::default(),
            cache: Default::default(),
            iteration_index: 0,
            iteration_entries: Vec::new(),
            context: Mutex::new(context),
        };

        // Load indexes by scanning directory structure (no unsealing!)
        adapter.indexes = adapter.load_credential_paths()?;

        Ok(adapter)
    }

    /// Get the filename for a credential based on credential ID
    /// Format: {cred_id_hex}.tpm
    /// The credential ID is hex-encoded for safe, unique filenames
    fn get_filename(cred_id: &[u8]) -> String {
        let cred_id_hex: String = cred_id.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}.tpm", cred_id_hex)
    }

    /// Parse credential ID from filename
    /// Returns None if filename doesn't match expected format
    fn parse_cred_id_from_filename(filename: &str) -> Option<Vec<u8>> {
        // Remove .tpm extension
        let name = filename.strip_suffix(".tpm")?;

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

    /// Get the full path for a credential file
    /// Structure: {storage_dir}/{rp_id}/{cred_id_hex}.tpm
    fn get_credential_path(&self, rp_id: &str, cred_id: &[u8]) -> PathBuf {
        self.storage_dir
            .join(rp_id)
            .join(Self::get_filename(cred_id))
    }

    /// Load all credential paths into the indexes
    /// Scans directories (rp_id) and files (cred_id_hex.tpm) within
    /// Builds three indexes: by credential ID, by RP ID, and by RP hash
    /// NO UNSEALING NEEDED - credential ID is extracted from filename
    fn load_credential_paths(&self) -> Result<CredentialIndexes> {
        debug!("Loading credential paths from TPM storage (no unsealing)");

        // List all directories in the storage (each directory is an rp_id)
        let entries = match std::fs::read_dir(&self.storage_dir) {
            Ok(entries) => entries,
            Err(e) => {
                debug!("Failed to read storage directory: {}", e);
                return Ok(CredentialIndexes::default());
            }
        };

        // Collect all valid RP directories
        let rp_dirs: Vec<(String, PathBuf)> = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let path = entry.path();
                // Skip files and hidden directories
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

                // Read all .tpm files in this RP directory
                let tpm_files = match std::fs::read_dir(&rp_path) {
                    Ok(entries) => entries
                        .filter_map(|entry| entry.ok())
                        .filter_map(|entry| {
                            let path = entry.path();
                            // Only process .tpm files
                            if path.extension().and_then(|s| s.to_str()) == Some("tpm") {
                                Some(path)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>(),
                    Err(_) => Vec::new(),
                };

                // Process each credential file
                for cred_path in tpm_files {
                    // Extract credential ID from filename (no unsealing!)
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

    /// Create a primary storage key in the owner hierarchy
    ///
    /// This creates a transient primary key that can be used as a parent for sealing operations.
    /// The key is created with the same parameters each time, so it has the same handle.
    fn create_primary_key(&self, context: &mut Context) -> Result<tss_esapi::handles::KeyHandle> {
        // Create a primary storage key (RSA 2048, storage parent)
        let object_attributes = tss_esapi::attributes::ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .map_err(|e| {
                log::error!("Failed to build object attributes: {}", e);
                keylib::Error::Other
            })?;

        // For a storage key, we need to specify the symmetric algorithm used to encrypt child objects
        let rsa_params = PublicRsaParametersBuilder::new()
            .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
            .with_scheme(RsaScheme::Null)
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_exponent(RsaExponent::default())
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(true)
            .build()
            .map_err(|e| {
                log::error!("Failed to build RSA parameters: {}", e);
                keylib::Error::Other
            })?;

        let primary_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .map_err(|e| {
                log::error!("Failed to build primary key public: {}", e);
                keylib::Error::Other
            })?;

        let primary_key_result = context
            .create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
            .map_err(|e| {
                log::error!("Failed to create primary key: {}", e);
                keylib::Error::Other
            })?;

        Ok(primary_key_result.key_handle)
    }

    /// Create a keyed hash object public structure for sealing data
    fn create_sealing_public(&self) -> Result<Public> {
        // For a sealing object, we need minimal attributes
        let object_attributes = tss_esapi::attributes::ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .build()
            .map_err(|e| {
                log::error!("Failed to build sealing object attributes: {}", e);
                keylib::Error::Other
            })?;

        // Create keyed hash parameters for sealing (Null scheme)
        let keyed_hash_params = PublicKeyedHashParameters::new(KeyedHashScheme::Null);

        // Build the sealing object with required unique identifier
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(keyed_hash_params)
            .with_keyed_hash_unique_identifier(tss_esapi::structures::Digest::default())
            .build()
            .map_err(|e| {
                log::error!("Failed to build sealing object public: {}", e);
                keylib::Error::Other
            })
    }

    /// Seal data using TPM with hybrid encryption
    ///
    /// Uses AES-256-GCM to encrypt the data, then seals only the encryption key with TPM.
    /// This avoids TPM size limits on sealed data (typically 128 bytes).
    fn seal_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        debug!("Sealing {} bytes with TPM (hybrid encryption)", data.len());

        // Generate a random 256-bit AES key
        let mut aes_key = [0u8; 32];
        OsRng.fill_bytes(&mut aes_key);

        // Generate a random 96-bit nonce for AES-GCM
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        // Encrypt the credential data with AES-GCM
        let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| {
            log::error!("Failed to create AES cipher: {}", e);
            keylib::Error::Other
        })?;

        let encrypted_data = cipher.encrypt(nonce, data).map_err(|e| {
            log::error!("Failed to encrypt data with AES-GCM: {}", e);
            keylib::Error::Other
        })?;

        debug!(
            "Encrypted {} bytes to {} bytes, now sealing 32-byte AES key with TPM",
            data.len(),
            encrypted_data.len()
        );

        // Now seal only the AES key (32 bytes) with TPM
        let mut context = self.context.lock().map_err(|e| {
            log::error!("Failed to lock TPM context: {}", e);
            keylib::Error::Other
        })?;

        // Create primary key
        let primary_key = self.create_primary_key(&mut context)?;

        // Create sealing object public
        let sealing_pub = self.create_sealing_public()?;

        // Create the sealed object with the AES key
        let sensitive_data = tss_esapi::structures::SensitiveData::try_from(aes_key.to_vec())
            .map_err(|e| {
                log::error!("Failed to create sensitive data for AES key: {}", e);
                keylib::Error::Other
            })?;

        let create_result = context
            .create(
                primary_key,
                sealing_pub,
                None,
                Some(sensitive_data),
                None,
                None,
            )
            .map_err(|e| {
                log::error!("Failed to create sealed object: {}", e);
                keylib::Error::Other
            })?;

        // Flush the primary key (we'll recreate it when unsealing)
        context.flush_context(primary_key.into()).map_err(|e| {
            log::error!("Failed to flush primary key: {}", e);
            keylib::Error::Other
        })?;

        let private_tpm: TPM2B_PRIVATE = create_result.out_private.into();
        // Store just the actual data, not the whole buffer
        let private_bytes = private_tpm.buffer[..private_tpm.size as usize].to_vec();

        #[allow(clippy::unnecessary_fallible_conversions)]
        let public_tpm: TPM2B_PUBLIC = create_result.out_public.try_into().map_err(|e| {
            log::error!("Failed to convert public to TPM2B: {:?}", e);
            keylib::Error::Other
        })?;

        // For Public, we need to store the entire TPM2B_PUBLIC structure as bytes
        // because it has a complex nested structure
        let public_bytes = unsafe {
            let ptr = &public_tpm as *const TPM2B_PUBLIC as *const u8;
            std::slice::from_raw_parts(ptr, std::mem::size_of::<TPM2B_PUBLIC>()).to_vec()
        };

        let sealed_blob = SealedBlob {
            encrypted_data,
            nonce: nonce_bytes.to_vec(),
            tpm_private: private_bytes,
            tpm_public: public_bytes,
        };

        // Serialize the blob to JSON
        serde_json::to_vec(&sealed_blob).map_err(|e| {
            log::error!("Failed to serialize sealed blob: {}", e);
            keylib::Error::Other
        })
    }

    /// Unseal data using TPM with hybrid decryption
    ///
    /// Unseals the AES key from TPM, then decrypts the data with AES-GCM.
    fn unseal_data(&self, sealed_data: &[u8]) -> Result<Vec<u8>> {
        debug!("Unsealing data with TPM (hybrid decryption)");

        let mut context = self.context.lock().map_err(|e| {
            log::error!("Failed to lock TPM context: {}", e);
            keylib::Error::Other
        })?;

        let sealed_blob: SealedBlob = serde_json::from_slice(sealed_data).map_err(|e| {
            log::error!("Failed to deserialize sealed blob: {}", e);
            keylib::Error::Other
        })?;

        let primary_key = self.create_primary_key(&mut context)?;

        let mut private_tpm = TPM2B_PRIVATE {
            size: sealed_blob.tpm_private.len() as u16,
            buffer: [0u8; 1550],
        };
        private_tpm.buffer[..sealed_blob.tpm_private.len()]
            .copy_from_slice(&sealed_blob.tpm_private);

        let public_tpm: TPM2B_PUBLIC = unsafe {
            let mut public_struct: TPM2B_PUBLIC = std::mem::zeroed();
            let ptr = &mut public_struct as *mut TPM2B_PUBLIC as *mut u8;
            std::ptr::copy_nonoverlapping(
                sealed_blob.tpm_public.as_ptr(),
                ptr,
                std::cmp::min(
                    sealed_blob.tpm_public.len(),
                    std::mem::size_of::<TPM2B_PUBLIC>(),
                ),
            );
            public_struct
        };

        // Convert to tss-esapi types
        let private = tss_esapi::structures::Private::try_from(private_tpm).map_err(|e| {
            log::error!("Failed to convert TPM2B_PRIVATE to Private: {}", e);
            keylib::Error::Other
        })?;

        let public = tss_esapi::structures::Public::try_from(public_tpm).map_err(|e| {
            log::error!("Failed to convert TPM2B_PUBLIC to Public: {}", e);
            keylib::Error::Other
        })?;

        // Load the sealed object
        let sealed_handle = context.load(primary_key, private, public).map_err(|e| {
            log::error!("Failed to load sealed object: {}", e);
            keylib::Error::Other
        })?;

        // Unseal the AES key from TPM
        let unsealed_key = context.unseal(sealed_handle.into()).map_err(|e| {
            log::error!("Failed to unseal AES key: {}", e);
            keylib::Error::Other
        })?;

        // Flush handles
        context.flush_context(sealed_handle.into()).map_err(|e| {
            log::error!("Failed to flush sealed handle: {}", e);
            keylib::Error::Other
        })?;

        context.flush_context(primary_key.into()).map_err(|e| {
            log::error!("Failed to flush primary key: {}", e);
            keylib::Error::Other
        })?;

        // Drop the mutex before AES decryption
        drop(context);

        // Extract the AES key
        let aes_key = unsealed_key.value();
        if aes_key.len() != 32 {
            log::error!(
                "Unsealed key has wrong size: {} (expected 32)",
                aes_key.len()
            );
            return Err(keylib::Error::Other);
        }

        // Decrypt the data with AES-GCM
        let nonce = Nonce::from_slice(&sealed_blob.nonce);
        let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|e| {
            log::error!("Failed to create AES cipher: {}", e);
            keylib::Error::Other
        })?;

        let decrypted_data = cipher
            .decrypt(nonce, sealed_blob.encrypted_data.as_ref())
            .map_err(|e| {
                log::error!("Failed to decrypt data with AES-GCM: {}", e);
                keylib::Error::Other
            })?;

        debug!("Successfully decrypted {} bytes", decrypted_data.len());

        Ok(decrypted_data)
    }

    /// Evict all expired cache entries
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

    /// Read a credential from a specific file path WITHOUT caching
    /// Used for operations that need &self
    fn read_credential_from_path_no_cache(&self, path: &Path) -> Result<Credential> {
        debug!("Reading credential (no cache) from path: {:?}", path);

        let mut file = File::open(path).map_err(|e| {
            log::error!("Failed to open credential file {}: {}", path.display(), e);
            keylib::Error::DoesNotExist
        })?;

        let mut sealed_data = Vec::new();
        file.read_to_end(&mut sealed_data).map_err(|e| {
            log::error!("Failed to read credential file {}: {}", path.display(), e);
            keylib::Error::Other
        })?;

        // Unseal the data using TPM
        let unsealed_data = self.unseal_data(&sealed_data)?;

        Credential::from_bytes(&unsealed_data)
    }

    /// Read a credential from a specific file path
    /// Uses time-limited cache to avoid redundant TPM unsealing
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
            "Cache MISS - reading and unsealing credential from path: {:?}",
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

        let mut file = File::open(path).map_err(|e| {
            log::error!("Failed to open credential file {}: {}", path.display(), e);
            keylib::Error::DoesNotExist
        })?;

        let mut sealed_data = Vec::new();
        file.read_to_end(&mut sealed_data).map_err(|e| {
            log::error!("Failed to read credential file {}: {}", path.display(), e);
            keylib::Error::Other
        })?;

        // Unseal the data using TPM
        let unsealed_data = self.unseal_data(&sealed_data)?;

        let credential = Credential::from_bytes(&unsealed_data)?;

        // Cache the unsealed credential with expiry time
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

    /// Read a credential by its ID
    fn read_credential_by_id(&mut self, id: &[u8]) -> Result<Credential> {
        debug!("Reading credential by ID: {:02x?}", &id[..id.len().min(8)]);

        let path = self
            .indexes
            .id
            .get(id)
            .ok_or_else(|| {
                debug!("Credential not found in index");
                keylib::Error::DoesNotExist
            })?
            .clone();

        self.read_credential_from_path(&path)
    }

    /// Load all credentials from storage (non-caching version)
    /// Used for operations that need &self
    fn load_all_credentials_no_cache(&self) -> Vec<Credential> {
        debug!("Loading all credentials from storage (no cache)");
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
            return Err(keylib::Error::DoesNotExist);
        }

        let path = self.iteration_entries[self.iteration_index].clone();
        self.iteration_index += 1;

        self.read_credential_from_path(&path)
    }


    /// Write a credential to storage
    /// Uses new directory structure: {storage_dir}/{rp_id}/{cred_id_hex}.tpm
    fn write_credential(&mut self, cred: &Credential) -> Result<()> {
        self.evict_expired_cache_entries();

        let path = self.get_credential_path(&cred.rp.id, &cred.id);
        debug!("Writing credential to: {:?}", path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                debug!("Failed to create directory: {}", e);
                keylib::Error::Other
            })?;
        }

        let bytes = cred.to_bytes()?;

        // Seal the data using TPM
        let sealed_data = self.seal_data(&bytes)?;

        let mut file = File::create(&path).map_err(|e| {
            log::error!("Failed to create credential file {}: {}", path.display(), e);
            keylib::Error::Other
        })?;

        file.write_all(&sealed_data).map_err(|e| {
            log::error!("Failed to write credential file {}: {}", path.display(), e);
            keylib::Error::Other
        })?;

        debug!("Successfully wrote and sealed credential");

        // Update all indexes
        self.indexes.id.insert(cred.id.to_vec(), path.clone());

        self.indexes
            .rp
            .entry(cred.rp.id.clone())
            .or_default()
            .push(path.clone());

        let mut hasher = Sha256::new();
        hasher.update(cred.rp.id.as_bytes());
        let rp_hash: [u8; 32] = hasher.finalize().into();
        self.indexes
            .rp_hash
            .entry(rp_hash)
            .or_default()
            .push(path);

        Ok(())
    }

    /// Delete a credential from storage
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
                keylib::Error::DoesNotExist
            })?
            .clone();

        // Read credential to get RP info for index cleanup
        let cred = self.read_credential_from_path(&path)?;

        // Delete the file
        std::fs::remove_file(&path).map_err(|e| {
            debug!("Failed to delete file: {}", e);
            keylib::Error::Other
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
}

impl CredentialStorage for TpmStorageAdapter {
    fn read_first(&mut self, filter: CredentialFilter) -> Result<Credential> {
        self.evict_expired_cache_entries();

        debug!("read_first called with filter: {:?}", filter);

        // Initialize iteration using the appropriate index
        self.iteration_entries = match &filter {
            CredentialFilter::None => {
                // No filter: iterate all credentials
                self.indexes.id.values().cloned().collect()
            }
            CredentialFilter::ById(id) => {
                // ById: direct lookup in index
                if let Some(path) = self.indexes.id.get(id.as_slice()) {
                    vec![path.clone()]
                } else {
                    Vec::new()
                }
            }
            CredentialFilter::ByRp(rp_id) => {
                // ByRp: lookup in index
                if let Some(paths) = self.indexes.rp.get(rp_id.as_str()) {
                    paths.clone()
                } else {
                    Vec::new()
                }
            }
            CredentialFilter::ByHash(hash) => {
                // ByHash: lookup in index
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

        self.find_next()
    }

    fn read_next(&mut self) -> Result<Credential> {
        self.evict_expired_cache_entries();

        debug!("read_next called");
        self.find_next()
    }

    fn read(&mut self, id: &str, _rp: &str) -> Result<Vec<u8>> {
        self.evict_expired_cache_entries();

        debug!("read called with id: {}", id);

        let id_bytes = id.as_bytes();
        let cred = self.read_credential_by_id(id_bytes)?;

        cred.to_bytes()
    }

    fn write(&mut self, _id: &str, _rp: &str, cred_ref: CredentialRef) -> Result<()> {
        self.evict_expired_cache_entries();

        debug!("write called for RP: {}", cred_ref.rp_id);

        let mut credential = cred_ref.to_owned();
        credential.sign_count = 0;
        credential.created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        credential.discoverable = true;

        self.write_credential(&credential)
    }

    fn delete(&mut self, id: &str) -> Result<()> {
        self.evict_expired_cache_entries();

        debug!("delete called with id: {}", id);
        let id_bytes = id.as_bytes();
        self.delete_credential(id_bytes)
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

    fn get_relying_parties(&self) -> Result<Vec<RelyingParty>> {
        debug!("get_relying_parties called");

        let credentials = self.load_all_credentials_no_cache();

        let rp_list: Vec<RelyingParty> = credentials.into_iter().map(|c| c.rp).collect();
        debug!("Found {} relying parties", rp_list.len());
        Ok(rp_list)
    }

    fn disable_user_verification(&self) -> bool {
        // TPM backend supports user verification
        false
    }

    fn cleanup_expired_cache(&mut self) {
        self.evict_expired_cache_entries();
    }
}
