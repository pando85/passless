//! TPM (Trusted Platform Module) storage adapter
//!
//! This adapter implements the CredentialStorage trait using TPM 2.0 for secure credential storage.
//! Credentials are sealed using the TPM, ensuring they can only be unsealed on the same machine.
//!
//! The implementation uses:
//! - TPM2_CreatePrimary to create a primary storage key in the owner hierarchy
//! - TPM2_Create to seal the credential data under the primary key
//! - TPM2_Load and TPM2_Unseal to retrieve sealed credentials

use crate::storage::{CredentialFilter, CredentialStorage};

use keylib::credential::RelyingParty;
use keylib::{Credential, CredentialRef, Result};

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

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

/// TPM storage adapter
///
/// Stores credentials as TPM-sealed files in a directory.
/// Each file contains a serialized SealedBlob with the private and public parts
/// of a sealed object created with the TPM.
pub struct TpmStorageAdapter {
    storage_dir: PathBuf,
    iteration_index: usize,
    iteration_files: Vec<PathBuf>,
    iteration_filter: CredentialFilter,
    context: Mutex<Context>,
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

        Ok(Self {
            storage_dir,
            iteration_index: 0,
            iteration_files: Vec::new(),
            iteration_filter: CredentialFilter::None,
            context: Mutex::new(context),
        })
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

    /// Load all credentials from storage
    fn load_all_credentials(&self) -> Vec<Credential> {
        let mut credentials = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.storage_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(file_type) = entry.file_type()
                    && file_type.is_file()
                    && path.extension().is_some_and(|ext| ext == "tpm")
                    && let Ok(cred) = self.load_credential(&path)
                {
                    credentials.push(cred);
                }
            }
        }

        credentials
    }

    /// Load and unseal a credential from a file
    fn load_credential(&self, path: &PathBuf) -> Result<Credential> {
        debug!("Loading credential from: {}", path.display());

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

    /// Save a credential to a file, sealed by TPM
    fn save_credential(&self, cred: &Credential) -> Result<()> {
        let filename = self.get_filename_for_cred(&cred.user.id);
        let path = self.storage_dir.join(filename);

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

        debug!("Credential saved and sealed: {}", path.display());
        Ok(())
    }

    /// Generate a filename for a credential based on user ID
    fn get_filename_for_cred(&self, user_id: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(user_id);
        let hash: [u8; 32] = hasher.finalize().into();
        format!(
            "cred_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.tpm",
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
        )
    }

    /// Find the next credential matching the current filter
    fn find_next(&mut self) -> Result<Credential> {
        while self.iteration_index < self.iteration_files.len() {
            let path = &self.iteration_files[self.iteration_index].clone();
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

impl CredentialStorage for TpmStorageAdapter {
    fn read_first(&mut self, filter: CredentialFilter) -> Result<Credential> {
        // Reset iteration
        self.iteration_index = 0;
        self.iteration_files.clear();
        self.iteration_filter = filter;

        // Load all credential file paths
        if let Ok(entries) = fs::read_dir(&self.storage_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(file_type) = entry.file_type()
                    && file_type.is_file()
                    && path.extension().is_some_and(|ext| ext == "tpm")
                {
                    self.iteration_files.push(path);
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
                fs::remove_file(path).map_err(|e| {
                    log::error!("Failed to delete credential file: {}", e);
                    keylib::Error::Other
                })?;
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
