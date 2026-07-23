//! TPM (Trusted Platform Module) storage adapter

pub mod init;
pub mod migrate;
pub mod portable;

use crate::storage::credential::Credential;
use crate::storage::index::{
    CredentialCache, CredentialIndexes, CredentialPathInfo, get_credential_path,
    load_credential_paths, update_indexes_on_delete, update_indexes_on_write,
};
use crate::storage::rp_id::validate_rp_id_for_storage;
use crate::storage::{CredentialFilter, CredentialStorage};
use crate::util::{atomic_write_in_dir, bytes_to_hex, create_secure_dir_all};

use soft_fido2::Result;

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Instant;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use log::{debug, info};
use rand::RngCore;
use rand::rngs::OsRng;
use tss_esapi::constants::SessionType;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy};
use tss_esapi::structures::{KeyedHashScheme, Public, PublicBuilder, PublicKeyedHashParameters};

use tss_esapi::structures::{
    PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::{TPM2B_PRIVATE, TPM2B_PUBLIC};
use tss_esapi::{Context, Tcti};
use zeroize::Zeroizing;

/// TPM storage adapter
///
/// Stores credentials as TPM-sealed files in a directory structure.
/// File structure: {storage_dir}/{rp_id}/{cred_id_hex}.tpm
/// Uses indexes for efficient lookups without unsealing all credentials.
pub struct TpmStorageAdapter {
    storage_dir: PathBuf,
    indexes: CredentialIndexes,
    cache: CredentialCache,
    iteration_index: usize,
    iteration_entries: Vec<PathBuf>,
    context: Mutex<Context>,
    portable: bool,
}

impl TpmStorageAdapter {
    #[allow(dead_code)]
    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }
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

/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256)
const COSE_ALG_ES256: i32 = -7;

fn aes_gcm_encrypt_with_aad(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
        log::error!("Failed to create AES cipher: {}", e);
        soft_fido2::Error::Other
    })?;
    let nonce = Nonce::try_from(nonce).expect("valid nonce length");
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| {
            log::error!("Failed to encrypt data with AES-GCM: {}", e);
            soft_fido2::Error::Other
        })
}

fn aes_gcm_decrypt_with_aad(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
        log::error!("Failed to create AES cipher: {}", e);
        soft_fido2::Error::Other
    })?;
    let nonce = Nonce::try_from(nonce).expect("valid nonce length");
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| {
            log::error!("Failed to decrypt data with AES-GCM: {}", e);
            soft_fido2::Error::Other
        })
}

fn build_metadata_aad(credential_id: &[u8], rp_id: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    aad.extend_from_slice(credential_id);
    aad.extend_from_slice(&(rp_id.len() as u16).to_be_bytes());
    aad.extend_from_slice(rp_id.as_bytes());
    aad.extend_from_slice(&COSE_ALG_ES256.to_be_bytes());
    aad.extend_from_slice(&portable::parent::FORMAT_VERSION.to_be_bytes());
    aad
}

fn build_aad_from_path(path: &Path, storage_dir: &Path) -> Result<Vec<u8>> {
    let rel = path.strip_prefix(storage_dir).map_err(|_| {
        log::error!("Failed to strip storage_dir prefix from credential path");
        soft_fido2::Error::Other
    })?;
    let components: Vec<_> = rel.components().collect();
    if components.len() != 2 {
        log::error!("Unexpected credential path structure: {:?}", path);
        return Err(soft_fido2::Error::Other);
    }
    let rp_id = components[0].as_os_str().to_str().ok_or_else(|| {
        log::error!("Non-UTF8 RP ID in path");
        soft_fido2::Error::Other
    })?;
    let cred_id_hex = components[1].as_os_str().to_str().ok_or_else(|| {
        log::error!("Non-UTF8 credential ID in path");
        soft_fido2::Error::Other
    })?;
    let cred_id_hex = cred_id_hex.strip_suffix(".tpm").ok_or_else(|| {
        log::error!("Missing .tpm extension in path");
        soft_fido2::Error::Other
    })?;
    let cred_id = hex::decode(cred_id_hex).map_err(|e| {
        log::error!("Failed to decode credential ID hex: {}", e);
        soft_fido2::Error::Other
    })?;
    let mut aad = Vec::new();
    aad.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    aad.extend_from_slice(&cred_id);
    aad.extend_from_slice(&(rp_id.len() as u16).to_be_bytes());
    aad.extend_from_slice(rp_id.as_bytes());
    aad.extend_from_slice(&COSE_ALG_ES256.to_be_bytes());
    aad.extend_from_slice(&portable::parent::FORMAT_VERSION.to_be_bytes());
    Ok(aad)
}

impl TpmStorageAdapter {
    pub fn new_with_options(
        storage_dir: PathBuf,
        tcti: Option<String>,
        allow_create_without_prompt: bool,
    ) -> Result<Self> {
        let allow_create_without_prompt = cfg!(debug_assertions) && allow_create_without_prompt;
        info!("Using TPM 2.0 backend");
        info!("Storage path: {}", storage_dir.display());

        // Ensure the storage directory is initialized
        // This will prompt the user via notifications if not initialized
        self::init::ensure_initialized(&storage_dir, allow_create_without_prompt)
            .map_err(|_| soft_fido2::Error::Other)?;

        // Initialize TPM context
        let tcti_conf = if let Some(ref tcti_str) = tcti {
            info!("Using TCTI configuration: {}", tcti_str);
            Tcti::from_str(tcti_str).map_err(|e| {
                log::error!("Failed to parse TCTI configuration '{}': {}", tcti_str, e);
                log::error!("TCTI format examples:");
                log::error!("  - Hardware TPM: device:/dev/tpmrm0");
                log::error!("  - swtpm socket: swtpm:path=/path/to/socket");

                soft_fido2::Error::Other
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
            soft_fido2::Error::Other
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
                soft_fido2::Error::Other
            })?
            .ok_or_else(|| {
                log::error!("TPM auth session returned None");
                soft_fido2::Error::Other
            })?;

        context.set_sessions((Some(session), None, None));

        info!("TPM context initialized successfully");

        // Load indexes by scanning directory structure (no unsealing!)
        let indexes = load_credential_paths(&storage_dir, "tpm").map_err(|e| {
            log::error!("Failed to load credential paths: {}", e);
            soft_fido2::Error::Other
        })?;

        let adapter = Self {
            storage_dir,
            indexes,
            cache: Default::default(),
            iteration_index: 0,
            iteration_entries: Vec::new(),
            context: Mutex::new(context),
            portable: false,
        };

        Ok(adapter)
    }

    /// Create a new TPM storage adapter in portable mode.
    ///
    /// In portable mode, the metadata AES key is sealed under the portable
    /// parent (persistent ECC P-256 storage key at handle 0x81000001),
    /// making sealed records loadable on any TPM provisioned from the same
    /// recovery seed.
    pub fn new_portable(
        storage_dir: PathBuf,
        tcti: Option<String>,
        allow_create_without_prompt: bool,
    ) -> Result<Self> {
        let metadata_path = storage_dir.join("portable_parent.json");
        if !metadata_path.exists() {
            log::error!(
                "TPM portable parent is not provisioned at {}",
                storage_dir.display()
            );
            log::error!("Run: passless tpm provision");
            return Err(soft_fido2::Error::Other);
        }

        let mut adapter = Self::new_with_options(storage_dir, tcti, allow_create_without_prompt)?;
        adapter.portable = true;
        info!("TPM storage adapter initialized in portable mode");
        Ok(adapter)
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
                soft_fido2::Error::Other
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
                soft_fido2::Error::Other
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
                soft_fido2::Error::Other
            })?;

        let primary_key_result = context
            .create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
            .map_err(|e| {
                log::error!("Failed to create primary key: {}", e);
                soft_fido2::Error::Other
            })?;

        Ok(primary_key_result.key_handle)
    }

    /// Get the parent key handle for sealing operations.
    ///
    /// In portable mode, returns the persistent portable parent handle.
    /// In legacy mode, creates and returns a transient primary key.
    fn sealing_parent_handle(
        &self,
        context: &mut Context,
    ) -> Result<tss_esapi::handles::KeyHandle> {
        if self.portable {
            let metadata_path = self.storage_dir.join("portable_parent.json");
            let metadata_bytes = std::fs::read(&metadata_path).map_err(|e| {
                log::error!("Failed to read portable parent metadata: {}", e);
                soft_fido2::Error::Other
            })?;
            let metadata: portable::parent::PortableParentMetadata =
                serde_json::from_slice(&metadata_bytes).map_err(|e| {
                    log::error!("Failed to parse portable parent metadata: {}", e);
                    soft_fido2::Error::Other
                })?;

            let persistent_tpm_handle = tss_esapi::handles::PersistentTpmHandle::new(
                metadata.persistent_handle,
            )
            .map_err(|e| {
                log::error!("Failed to create persistent TPM handle: {}", e);
                soft_fido2::Error::Other
            })?;

            // Clear sessions before registering the persistent handle
            // The HMAC session we use for encryption interferes with tr_from_tpm_public
            let saved_sessions = context.sessions();
            context.set_sessions((None, None, None));

            let persistent_handle = context
                .tr_from_tpm_public(persistent_tpm_handle.into())
                .map_err(|e| {
                    log::error!(
                        "Failed to register persistent handle in ESYS context: {}",
                        e
                    );
                    soft_fido2::Error::Other
                })?;

            // Restore sessions
            context.set_sessions(saved_sessions);

            Ok(tss_esapi::handles::KeyHandle::from(persistent_handle))
        } else {
            self.create_primary_key(context)
        }
    }

    /// Create a keyed hash object public structure for sealing data
    fn create_sealing_public(&self) -> Result<Public> {
        let fixed_tpm = !self.portable;
        let fixed_parent = !self.portable;

        let object_attributes = tss_esapi::attributes::ObjectAttributesBuilder::new()
            .with_fixed_tpm(fixed_tpm)
            .with_fixed_parent(fixed_parent)
            .with_user_with_auth(true)
            .build()
            .map_err(|e| {
                log::error!("Failed to build sealing object attributes: {}", e);
                soft_fido2::Error::Other
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
                soft_fido2::Error::Other
            })
    }

    /// Seal data using TPM with hybrid encryption
    ///
    /// Uses AES-256-GCM to encrypt the data, then seals only the encryption key with TPM.
    /// This avoids TPM size limits on sealed data (typically 128 bytes).
    ///
    /// The `aad` parameter provides additional authenticated data bound into the AES-GCM
    /// ciphertext. For the portable path, callers pass credential-specific AAD (cred ID,
    /// RP ID, algorithm, provider version); the TPM public blob is appended internally.
    /// For the legacy path, pass an empty slice.
    pub fn seal_data(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        debug!("Sealing {} bytes with TPM (hybrid encryption)", data.len());

        let mut aes_key = [0u8; 32];
        OsRng.fill_bytes(&mut aes_key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let mut context = self.context.lock().map_err(|e| {
            log::error!("Failed to lock TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        let parent_key = self.sealing_parent_handle(&mut context)?;
        let sealing_pub = self.create_sealing_public()?;

        let sensitive_data = tss_esapi::structures::SensitiveData::try_from(aes_key.to_vec())
            .map_err(|e| {
                log::error!("Failed to create sensitive data for AES key: {}", e);
                soft_fido2::Error::Other
            })?;

        let create_result = context
            .create(
                parent_key,
                sealing_pub,
                None,
                Some(sensitive_data),
                None,
                None,
            )
            .map_err(|e| {
                log::error!("Failed to create sealed object: {}", e);
                soft_fido2::Error::Other
            })?;

        if !self.portable {
            context.flush_context(parent_key.into()).map_err(|e| {
                log::error!("Failed to flush parent key: {}", e);
                soft_fido2::Error::Other
            })?;
        }

        let private_tpm: TPM2B_PRIVATE = create_result.out_private.into();
        let private_bytes = private_tpm.buffer[..private_tpm.size as usize].to_vec();

        let public_bytes = if self.portable {
            create_result.out_public.marshall().map_err(|e| {
                log::error!("Failed to marshall public area: {}", e);
                soft_fido2::Error::Other
            })?
        } else {
            #[allow(clippy::unnecessary_fallible_conversions)]
            let public_tpm: TPM2B_PUBLIC = create_result.out_public.try_into().map_err(|e| {
                log::error!("Failed to convert public to TPM2B: {:?}", e);
                soft_fido2::Error::Other
            })?;

            unsafe {
                let ptr = &public_tpm as *const TPM2B_PUBLIC as *const u8;
                std::slice::from_raw_parts(ptr, std::mem::size_of::<TPM2B_PUBLIC>()).to_vec()
            }
        };

        let mut full_aad = Vec::with_capacity(aad.len() + public_bytes.len());
        full_aad.extend_from_slice(aad);
        full_aad.extend_from_slice(&public_bytes);

        let encrypted_data = aes_gcm_encrypt_with_aad(&aes_key, &nonce_bytes, data, &full_aad)?;

        debug!(
            "Encrypted {} bytes to {} bytes with AAD ({} bytes)",
            data.len(),
            encrypted_data.len(),
            full_aad.len()
        );

        let sealed_blob = SealedBlob {
            encrypted_data,
            nonce: nonce_bytes.to_vec(),
            tpm_private: private_bytes,
            tpm_public: public_bytes,
        };

        let serialized = Zeroizing::new(serde_json::to_vec(&sealed_blob).map_err(|e| {
            log::error!("Failed to serialize sealed blob: {}", e);
            soft_fido2::Error::Other
        })?);

        Ok(serialized.to_vec())
    }

    /// Unseal data using TPM with hybrid decryption
    ///
    /// Unseals the AES key from TPM, then decrypts the data with AES-GCM.
    ///
    /// The `aad` parameter must match what was passed to `seal_data`. For the portable
    /// path, callers pass credential-specific AAD; the TPM public blob from the sealed
    /// blob is appended internally. For the legacy path, pass an empty slice.
    pub fn unseal_data(&self, sealed_data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        debug!("Unsealing data with TPM (hybrid decryption)");

        let mut context = self.context.lock().map_err(|e| {
            log::error!("Failed to lock TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        let sealed_blob: SealedBlob = serde_json::from_slice(sealed_data).map_err(|e| {
            log::error!("Failed to deserialize sealed blob: {}", e);
            soft_fido2::Error::Other
        })?;

        let parent_key = self.sealing_parent_handle(&mut context)?;

        let mut private_tpm = TPM2B_PRIVATE {
            size: sealed_blob.tpm_private.len() as u16,
            buffer: [0u8; 1550],
        };
        private_tpm.buffer[..sealed_blob.tpm_private.len()]
            .copy_from_slice(&sealed_blob.tpm_private);

        let private = tss_esapi::structures::Private::try_from(private_tpm).map_err(|e| {
            log::error!("Failed to convert TPM2B_PRIVATE to Private: {}", e);
            soft_fido2::Error::Other
        })?;

        let public = if self.portable {
            Public::unmarshall(&sealed_blob.tpm_public).map_err(|e| {
                log::error!("Failed to unmarshall public area: {}", e);
                soft_fido2::Error::Other
            })?
        } else {
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

            tss_esapi::structures::Public::try_from(public_tpm).map_err(|e| {
                log::error!("Failed to convert TPM2B_PUBLIC to Public: {}", e);
                soft_fido2::Error::Other
            })?
        };

        let sealed_handle = context.load(parent_key, private, public).map_err(|e| {
            log::error!("Failed to load sealed object: {}", e);
            soft_fido2::Error::Other
        })?;

        let unsealed_key = context.unseal(sealed_handle.into()).map_err(|e| {
            log::error!("Failed to unseal AES key: {}", e);
            soft_fido2::Error::Other
        })?;

        context.flush_context(sealed_handle.into()).map_err(|e| {
            log::error!("Failed to flush sealed handle: {}", e);
            soft_fido2::Error::Other
        })?;

        if !self.portable {
            context.flush_context(parent_key.into()).map_err(|e| {
                log::error!("Failed to flush parent key: {}", e);
                soft_fido2::Error::Other
            })?;
        }

        drop(context);

        let aes_key = unsealed_key.value();
        if aes_key.len() != 32 {
            log::error!(
                "Unsealed key has wrong size: {} (expected 32)",
                aes_key.len()
            );
            return Err(soft_fido2::Error::Other);
        }

        let mut full_aad = Vec::with_capacity(aad.len() + sealed_blob.tpm_public.len());
        full_aad.extend_from_slice(aad);
        full_aad.extend_from_slice(&sealed_blob.tpm_public);

        let decrypted_data = aes_gcm_decrypt_with_aad(
            aes_key,
            &sealed_blob.nonce,
            &sealed_blob.encrypted_data,
            &full_aad,
        )?;

        debug!("Successfully decrypted {} bytes", decrypted_data.len());

        Ok(decrypted_data)
    }

    /// Read a credential from a specific file path WITHOUT caching
    /// Used for operations that need &self
    #[allow(dead_code)]
    pub fn read_credential_from_path_no_cache(
        &self,
        path: &Path,
    ) -> Result<soft_fido2::Credential> {
        debug!("Reading credential (no cache) from path: {:?}", path);

        let mut file = File::open(path).map_err(|e| {
            log::error!("Failed to open credential file {}: {}", path.display(), e);
            soft_fido2::Error::DoesNotExist
        })?;

        let mut sealed_data = Vec::new();
        file.read_to_end(&mut sealed_data).map_err(|e| {
            log::error!("Failed to read credential file {}: {}", path.display(), e);
            soft_fido2::Error::Other
        })?;

        let aad = if self.portable {
            build_aad_from_path(path, &self.storage_dir)?
        } else {
            Vec::new()
        };

        let unsealed_data = Zeroizing::new(self.unseal_data(&sealed_data, &aad)?);

        Credential::from_bytes(&unsealed_data).map(|cred| cred.to_soft_fido2())
    }

    /// Read a credential from a specific file path
    /// Uses time-limited cache to avoid redundant TPM unsealing
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
            "Cache MISS - reading and unsealing credential from path: {:?}",
            path
        );

        self.cache.evict_expired();
        self.cache.evict_oldest_if_full();

        let mut file = File::open(path).map_err(|e| {
            log::error!("Failed to open credential file {}: {}", path.display(), e);
            soft_fido2::Error::DoesNotExist
        })?;

        let mut sealed_data = Vec::new();
        file.read_to_end(&mut sealed_data).map_err(|e| {
            log::error!("Failed to read credential file {}: {}", path.display(), e);
            soft_fido2::Error::Other
        })?;

        let aad = if self.portable {
            build_aad_from_path(path, &self.storage_dir)?
        } else {
            Vec::new()
        };

        let unsealed_data = Zeroizing::new(self.unseal_data(&sealed_data, &aad)?);

        let credential = Credential::from_bytes(&unsealed_data).map(|cred| cred.to_soft_fido2())?;

        self.cache.insert(path.to_path_buf(), credential.clone());

        Ok(credential)
    }

    /// Read a credential by its ID
    fn read_credential_by_id(&mut self, id: &[u8]) -> Result<soft_fido2::Credential> {
        let path_info = self.indexes.id.get(id).ok_or_else(|| {
            debug!("Credential not found in index");
            soft_fido2::Error::DoesNotExist
        })?;

        let path = path_info.to_path(&self.storage_dir);
        self.read_credential_from_path(&path)
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
            return Err(soft_fido2::Error::DoesNotExist);
        }

        let path = self.iteration_entries[self.iteration_index].clone();
        self.iteration_index += 1;

        self.read_credential_from_path(&path)
    }

    /// Write a credential to storage
    /// Uses new directory structure: {storage_dir}/{rp_id}/{cred_id_hex}.tpm
    #[allow(dead_code)]
    pub fn write_credential(&mut self, cred: &soft_fido2::Credential) -> Result<()> {
        self.cache.evict_expired();

        let rp_id = validate_rp_id_for_storage(cred.rp.id.as_str())
            .map_err(|_| soft_fido2::Error::Other)?;

        let path = get_credential_path(&self.storage_dir, &rp_id, &cred.id, "tpm");
        debug!("Writing credential to: {:?}", path);

        let parent = path.parent().ok_or(soft_fido2::Error::Other)?;
        create_secure_dir_all(parent).map_err(|e| {
            debug!("Failed to create directory: {}", e);
            soft_fido2::Error::Other
        })?;

        let our_cred = Credential::from_soft_fido2(cred);
        let bytes = Zeroizing::new(our_cred.to_bytes()?);

        let aad = if self.portable {
            build_metadata_aad(&cred.id, &rp_id)
        } else {
            Vec::new()
        };

        let sealed_data = self.seal_data(&bytes, &aad)?;

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(soft_fido2::Error::Other)?;
        atomic_write_in_dir(parent, filename, &sealed_data).map_err(|e| {
            log::error!("Failed to write credential file {}: {}", path.display(), e);
            soft_fido2::Error::Other
        })?;

        debug!("Successfully wrote and sealed credential");

        // Invalidate cache entry for this credential to ensure fresh reads
        self.cache.remove(&path);

        // Update all indexes using shared function
        let path_info = CredentialPathInfo::new(rp_id, cred.id.to_vec(), "tpm".to_string());
        update_indexes_on_write(&mut self.indexes, path_info);

        Ok(())
    }

    /// Delete a credential from storage
    fn delete_credential(&mut self, id: &[u8]) -> Result<()> {
        self.cache.evict_expired();

        debug!("Deleting credential with ID: {}", bytes_to_hex(id));

        let path_info = self
            .indexes
            .id
            .get(id)
            .ok_or_else(|| {
                debug!("Credential not found in index");
                soft_fido2::Error::DoesNotExist
            })?
            .clone();

        let path = path_info.to_path(&self.storage_dir);

        // Delete the file
        std::fs::remove_file(&path).map_err(|e| {
            debug!("Failed to delete file: {}", e);
            soft_fido2::Error::Other
        })?;

        // Remove from cache
        self.cache.remove(&path);

        // Remove from all indexes using shared function
        update_indexes_on_delete(&mut self.indexes, id);

        debug!("Successfully deleted credential");

        Ok(())
    }
}

impl CredentialStorage for TpmStorageAdapter {
    fn read_first(&mut self, filter: CredentialFilter) -> Result<soft_fido2::Credential> {
        self.cache.evict_expired();

        debug!("read_first called with filter: {:?}", filter);

        self.iteration_entries = self.indexes.resolve_filter(&filter, &self.storage_dir);
        self.iteration_index = 0;

        debug!(
            "Starting iteration with {} entries for filter: {:?}",
            self.iteration_entries.len(),
            filter
        );

        self.find_next()
    }

    fn read_next(&mut self) -> Result<soft_fido2::Credential> {
        self.cache.evict_expired();

        debug!("read_next called");
        self.find_next()
    }

    fn read(&mut self, id: &[u8]) -> Result<soft_fido2::Credential> {
        self.cache.evict_expired();

        debug!("read called with id: {}", bytes_to_hex(id));

        // Load and return credential directly (no re-serialization)
        self.read_credential_by_id(id)
    }

    fn write(&mut self, cred_ref: soft_fido2::CredentialRef) -> Result<()> {
        self.cache.evict_expired();

        debug!("write called for RP: {}", cred_ref.rp_id);

        // Just save the credential as provided by soft-fido2
        // This is called both during registration (new credential) and
        // during authentication (updating sign counter)
        let credential = cred_ref.to_owned();
        self.write_credential(&credential)
    }

    fn delete(&mut self, id: &[u8]) -> Result<()> {
        self.cache.evict_expired();

        debug!("delete called with id: {}", bytes_to_hex(id));
        self.delete_credential(id)
    }

    fn count_credentials(&self) -> usize {
        let count = self.indexes.id.len();
        debug!("count_credentials: {}", count);
        count
    }

    fn disable_user_verification(&self) -> bool {
        // TPM backend supports user verification
        false
    }

    fn cleanup_expired_cache(&mut self) {
        self.cache.evict_expired();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_aad_mismatch_fails_decryption() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let plaintext = b"credential metadata payload";
        let aad_a = b"aad-for-credential-A";
        let aad_b = b"aad-for-credential-B";

        let ciphertext =
            aes_gcm_encrypt_with_aad(&key, &nonce, plaintext, aad_a).expect("encrypt succeeds");

        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        let decrypted =
            aes_gcm_decrypt_with_aad(&key, &nonce, &ciphertext, aad_a).expect("correct AAD works");
        assert_eq!(decrypted, plaintext);

        let result = aes_gcm_decrypt_with_aad(&key, &nonce, &ciphertext, aad_b);
        assert!(result.is_err(), "decryption with wrong AAD must fail");

        let result_empty = aes_gcm_decrypt_with_aad(&key, &nonce, &ciphertext, b"");
        assert!(
            result_empty.is_err(),
            "decryption with empty AAD must fail when data was encrypted with non-empty AAD"
        );
    }

    #[test]
    fn aes_gcm_empty_aad_roundtrip() {
        let key = [0x55u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"legacy credential data";

        let ciphertext =
            aes_gcm_encrypt_with_aad(&key, &nonce, plaintext, b"").expect("encrypt succeeds");

        let decrypted =
            aes_gcm_decrypt_with_aad(&key, &nonce, &ciphertext, b"").expect("decrypt succeeds");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn build_metadata_aad_deterministic() {
        let cred_id = vec![0xAA, 0xBB, 0xCC];
        let rp_id = "example.com";

        let aad1 = build_metadata_aad(&cred_id, rp_id);
        let aad2 = build_metadata_aad(&cred_id, rp_id);
        assert_eq!(aad1, aad2);

        let aad_different = build_metadata_aad(&[0xDD, 0xEE], rp_id);
        assert_ne!(aad1, aad_different);
    }
}
