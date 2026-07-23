//! TPM credential key provider implementation
//!
//! Implements the `CredentialKeyProvider` trait for TPM-resident credential keys.

use super::parent::{self, PortableParent};
use super::session;

use soft_fido2::Result;
use soft_fido2_ctap::SecBytes;
use soft_fido2_ctap::key_provider::{
    CredentialKey, CredentialKeyError, CredentialKeyProvider, CredentialKeyProviderId,
    GeneratedCredentialKey,
};

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::OnceLock;

use log::{debug, error};
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::{AlgorithmIdentifier, CapabilityType, EccCurveIdentifier};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::{
    EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public, PublicBuilder,
    PublicEccParametersBuilder, SignatureScheme, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};

/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256)
const COSE_ALG_ES256: i32 = -7;

/// Validate that a record's format version is compatible with this binary.
///
/// Refuses records stamped with a version newer than `FORMAT_VERSION`
/// (downgrade protection) or version 0 (unknown/invalid).
pub fn validate_record_version(
    record_version: u16,
) -> core::result::Result<(), CredentialKeyError> {
    if record_version == 0 {
        error!(
            "Refusing record with unknown format version 0 (current version: {})",
            parent::FORMAT_VERSION
        );
        return Err(CredentialKeyError::UnsupportedFormatVersion);
    }
    if record_version > parent::FORMAT_VERSION {
        error!(
            "Refusing record with newer format version {} (current version: {}); \
             upgrade this binary before accessing this credential",
            record_version,
            parent::FORMAT_VERSION
        );
        return Err(CredentialKeyError::UnsupportedFormatVersion);
    }
    Ok(())
}

/// TPM credential key provider
pub struct TpmCredentialKeyProvider {
    parent: PortableParent,
    context: Mutex<Context>,
    capabilities_checked: OnceLock<bool>,
}

/// Opaque material format for TPM credential keys
#[derive(serde::Serialize, serde::Deserialize)]
struct TpmKeyMaterial {
    /// TPMT_PUBLIC marshalled (no size prefix)
    public_blob: Vec<u8>,
    /// TPM2B_PRIVATE inner content (no outer size prefix)
    private_blob: Vec<u8>,
    /// Uncompressed public key (0x04 || x || y)
    cose_public_key: Vec<u8>,
}

impl TpmCredentialKeyProvider {
    /// Create a new TPM credential key provider
    pub fn new(storage_dir: PathBuf, tcti: Option<String>) -> Result<Self> {
        let parent = PortableParent::new(storage_dir.clone(), tcti.clone())?;

        let tcti_conf = if let Some(ref tcti_str) = tcti {
            std::str::FromStr::from_str(tcti_str).map_err(|e| {
                error!("Failed to parse TCTI configuration: {}", e);
                soft_fido2::Error::Other
            })?
        } else {
            tss_esapi::Tcti::Device(Default::default())
        };

        let context = Context::new(tcti_conf).map_err(|e| {
            error!("Failed to create TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        Ok(Self {
            parent,
            context: Mutex::new(context),
            capabilities_checked: OnceLock::new(),
        })
    }

    /// Check if the provider is ready (parent is provisioned)
    pub fn is_ready(&self) -> bool {
        self.parent.is_provisioned()
    }

    fn verify_tpm_capabilities(&self) -> core::result::Result<(), CredentialKeyError> {
        if self.capabilities_checked.get().is_some() {
            return Ok(());
        }

        let mut context = self.context.lock().map_err(|e| {
            error!("Failed to lock TPM context for capability check: {}", e);
            CredentialKeyError::TransientFailure("Failed to lock TPM context".to_string())
        })?;

        let (alg_data, _) = context
            .get_capability(CapabilityType::Algorithms, 0, 256)
            .map_err(|e| {
                error!("TPM2_GetCapability(Algorithms) failed: {}", e);
                CredentialKeyError::TransientFailure(
                    "Failed to query TPM algorithm capabilities".to_string(),
                )
            })?;

        let alg_list = match alg_data {
            tss_esapi::structures::CapabilityData::Algorithms(list) => list,
            _ => {
                error!("Unexpected capability data type for Algorithms query");
                return Err(CredentialKeyError::TransientFailure(
                    "Unexpected TPM capability response".to_string(),
                ));
            }
        };

        let required_algs = [
            (AlgorithmIdentifier::Ecc, "ECC"),
            (AlgorithmIdentifier::EcDsa, "ECDSA"),
            (AlgorithmIdentifier::Aes, "AES"),
            (AlgorithmIdentifier::Cfb, "AES-CFB"),
        ];

        for (alg_id, name) in &required_algs {
            if alg_list.find(*alg_id).is_none() {
                error!(
                    "TPM does not support required algorithm {} ({:?})",
                    name, alg_id
                );
                return Err(CredentialKeyError::TransientFailure(format!(
                    "TPM missing required algorithm: {}",
                    name
                )));
            }
        }

        let (curve_data, _) = context
            .get_capability(CapabilityType::EccCurves, 0, 16)
            .map_err(|e| {
                error!("TPM2_GetCapability(EccCurves) failed: {}", e);
                CredentialKeyError::TransientFailure(
                    "Failed to query TPM ECC curve capabilities".to_string(),
                )
            })?;

        let curve_list = match curve_data {
            tss_esapi::structures::CapabilityData::EccCurves(list) => list,
            _ => {
                error!("Unexpected capability data type for EccCurves query");
                return Err(CredentialKeyError::TransientFailure(
                    "Unexpected TPM capability response".to_string(),
                ));
            }
        };

        if !curve_list.as_ref().contains(&EccCurveIdentifier::NistP256) {
            error!("TPM does not support required ECC curve NIST P-256");
            return Err(CredentialKeyError::TransientFailure(
                "TPM missing required ECC curve: NIST P-256".to_string(),
            ));
        }

        let _ = self.capabilities_checked.set(true);
        debug!("TPM capability check passed: ES256 (P-256, ECDSA-SHA256, AES-128-CFB) supported");
        Ok(())
    }

    pub fn import_existing_es256_key(
        &self,
        private_scalar: &[u8; 32],
    ) -> Result<GeneratedCredentialKey> {
        debug!("Importing existing ES256 key into TPM");

        let (pub_x, pub_y) = compute_public_from_scalar(private_scalar)?;

        let metadata = self.parent.load_metadata()?;
        self.parent.verify_parent(&metadata)?;

        let mut context = self.context.lock().map_err(|e| {
            error!("Failed to lock TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        let parent_tpm_handle =
            tss_esapi::handles::PersistentTpmHandle::new(metadata.persistent_handle)
                .map_err(|_| soft_fido2::Error::Other)?;
        let parent_obj = context
            .tr_from_tpm_public(parent_tpm_handle.into())
            .map_err(|e| {
                error!("Failed to register parent handle: {}", e);
                soft_fido2::Error::Other
            })?;
        let parent_handle = tss_esapi::handles::KeyHandle::from(parent_obj);

        let (parent_pub, _, _) = context.read_public(parent_handle).map_err(|e| {
            error!("Failed to read parent public: {}", e);
            soft_fido2::Error::Other
        })?;

        let (parent_x, parent_y) = match &parent_pub {
            Public::Ecc { unique, .. } => {
                let x = unique.x().value().to_vec();
                let y = unique.y().value().to_vec();
                let mut x_padded = vec![0u8; 32];
                let x_start = 32 - x.len();
                x_padded[x_start..].copy_from_slice(&x);
                let mut y_padded = vec![0u8; 32];
                let y_start = 32 - y.len();
                y_padded[y_start..].copy_from_slice(&y);
                (x_padded, y_padded)
            }
            _ => {
                error!("Expected ECC parent public key");
                return Err(soft_fido2::Error::Other);
            }
        };

        let child_public = parent::build_import_child_public(&pub_x, &pub_y)?;

        let mut child_seed = zeroize::Zeroizing::new(vec![0u8; 32]);
        {
            use hkdf::Hkdf;
            use sha2::Sha256;
            let hkdf = Hkdf::<Sha256>::new(Some(b"passless.child-seed"), private_scalar);
            hkdf.expand(b"child-import-seed", &mut child_seed)
                .map_err(|e| {
                    error!("HKDF expand failed for child seed: {}", e);
                    soft_fido2::Error::Other
                })?;
        }

        let (duplicate, in_sym_seed) = parent::wrap_child_for_import(
            private_scalar,
            &child_seed,
            &parent_x,
            &parent_y,
            &child_public,
        )?;

        let imported_private = session::execute_with_encrypted_session(&mut context, |ctx| {
            ctx.import(
                parent_handle.into(),
                None,
                child_public.clone(),
                duplicate,
                in_sym_seed,
                SymmetricDefinitionObject::Null,
            )
            .map_err(|e| {
                error!("Failed to import child key: {}", e);
                soft_fido2::Error::Other
            })
        })?;

        let public_blob = child_public.marshall().map_err(|e| {
            error!("Failed to marshall child public: {}", e);
            soft_fido2::Error::Other
        })?;

        let private_blob = imported_private.value().to_vec();

        let mut cose_public_key = vec![0x04];
        cose_public_key.extend_from_slice(&pub_x);
        cose_public_key.extend_from_slice(&pub_y);

        let material = TpmKeyMaterial {
            public_blob,
            private_blob,
            cose_public_key: cose_public_key.clone(),
        };

        let material_bytes = serde_json::to_vec(&material).map_err(|e| {
            error!("Failed to serialize imported key material: {}", e);
            soft_fido2::Error::Other
        })?;

        let key = CredentialKey::new(
            CredentialKeyProviderId::new(parent::PROVIDER_ID),
            parent::FORMAT_VERSION,
            SecBytes::from_slice(&material_bytes),
        );

        debug!("Imported existing ES256 key into TPM");

        Ok(GeneratedCredentialKey {
            key,
            cose_public_key,
        })
    }

    /// Generate a new ES256 credential key inside the TPM
    fn generate_es256_key(&self) -> Result<GeneratedCredentialKey> {
        debug!("Generating ES256 credential key in TPM");

        let metadata = self.parent.load_metadata()?;
        self.parent.verify_parent(&metadata)?;

        let mut context = self.context.lock().map_err(|e| {
            error!("Failed to lock TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        let parent_tpm_handle =
            tss_esapi::handles::PersistentTpmHandle::new(metadata.persistent_handle)
                .map_err(|_| soft_fido2::Error::Other)?;
        let parent_obj = context
            .tr_from_tpm_public(parent_tpm_handle.into())
            .map_err(|e| {
                error!("Failed to register parent handle: {}", e);
                soft_fido2::Error::Other
            })?;
        let parent_handle = tss_esapi::handles::KeyHandle::from(parent_obj);

        let key_public = build_signing_key_public()?;

        let create_result = session::execute_with_encrypted_session(&mut context, |ctx| {
            ctx.create(parent_handle, key_public, None, None, None, None)
                .map_err(|e| {
                    error!("Failed to create signing key: {}", e);
                    soft_fido2::Error::Other
                })
        })?;

        let public_blob = create_result.out_public.marshall().map_err(|e| {
            error!("Failed to marshall signing key public: {}", e);
            soft_fido2::Error::Other
        })?;

        let private_blob = create_result.out_private.value().to_vec();

        let cose_public_key = extract_cose_public_key(&create_result.out_public)?;

        let material = TpmKeyMaterial {
            public_blob,
            private_blob,
            cose_public_key: cose_public_key.clone(),
        };

        let material_bytes = serde_json::to_vec(&material).map_err(|e| {
            error!("Failed to serialize key material: {}", e);
            soft_fido2::Error::Other
        })?;

        let key = CredentialKey::new(
            CredentialKeyProviderId::new(parent::PROVIDER_ID),
            parent::FORMAT_VERSION,
            SecBytes::from_slice(&material_bytes),
        );

        debug!("Generated ES256 credential key in TPM");

        Ok(GeneratedCredentialKey {
            key,
            cose_public_key,
        })
    }

    /// Sign a message with a TPM credential key
    fn sign_with_tpm_key(
        &self,
        key_material: &[u8],
        message: &[u8],
    ) -> core::result::Result<Vec<u8>, CredentialKeyError> {
        debug!("Signing message with TPM credential key");

        let material: TpmKeyMaterial = serde_json::from_slice(key_material).map_err(|e| {
            error!("Failed to deserialize key material: {}", e);
            CredentialKeyError::InvalidKeyMaterial
        })?;

        let public = Public::unmarshall(&material.public_blob).map_err(|e| {
            error!("Failed to unmarshall public: {}", e);
            CredentialKeyError::InvalidKeyMaterial
        })?;

        validate_signing_template(&public)?;

        let mut context = self.context.lock().map_err(|e| {
            error!("Failed to lock TPM context: {}", e);
            CredentialKeyError::TransientFailure("Failed to lock TPM context".to_string())
        })?;

        let metadata = self.parent.load_metadata().map_err(|e| {
            error!("Failed to load parent metadata: {}", e);
            CredentialKeyError::TransientFailure("Failed to load parent".to_string())
        })?;

        let parent_tpm_handle = tss_esapi::handles::PersistentTpmHandle::new(
            metadata.persistent_handle,
        )
        .map_err(|_| CredentialKeyError::TransientFailure("Invalid parent handle".to_string()))?;
        let parent_obj = context
            .tr_from_tpm_public(parent_tpm_handle.into())
            .map_err(|e| {
                error!("Failed to register parent handle: {}", e);
                CredentialKeyError::TransientFailure("Failed to register parent handle".to_string())
            })?;
        let parent_handle = tss_esapi::handles::KeyHandle::from(parent_obj);

        let private = tss_esapi::structures::Private::try_from(material.private_blob.clone())
            .map_err(|e| {
                error!("Failed to create Private: {}", e);
                CredentialKeyError::InvalidKeyMaterial
            })?;

        let loaded_key = context
            .execute_with_nullauth_session(|ctx| ctx.load(parent_handle, private, public.clone()))
            .map_err(|e| {
                error!("Failed to load signing key: {}", e);
                CredentialKeyError::InvalidKeyMaterial
            })?;

        let result = (|| -> std::result::Result<Vec<u8>, CredentialKeyError> {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(message);

            let digest_tpm =
                tss_esapi::structures::Digest::try_from(digest.as_slice()).map_err(|e| {
                    error!("Failed to create Digest: {}", e);
                    CredentialKeyError::TransientFailure("Failed to create digest".to_string())
                })?;

            let null_ticket = create_null_hashcheck_ticket().map_err(|e| {
                error!("Failed to create null ticket: {}", e);
                CredentialKeyError::TransientFailure("Failed to create ticket".to_string())
            })?;

            let signature = context
                .execute_with_nullauth_session(|ctx| {
                    ctx.sign(
                        loaded_key,
                        digest_tpm,
                        SignatureScheme::EcDsa {
                            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                        },
                        null_ticket,
                    )
                })
                .map_err(|e| {
                    error!("Failed to sign with TPM: {}", e);
                    CredentialKeyError::TransientFailure("TPM signing failed".to_string())
                })?;

            signature_to_der(&signature)
        })();

        let _ = context.flush_context(loaded_key.into());

        result
    }
}

impl CredentialKeyProvider for TpmCredentialKeyProvider {
    fn provider_id(&self) -> CredentialKeyProviderId {
        CredentialKeyProviderId::new(parent::PROVIDER_ID)
    }

    fn supports_algorithm(&self, algorithm: i32) -> bool {
        if algorithm != COSE_ALG_ES256 {
            return false;
        }
        self.verify_tpm_capabilities().is_ok()
    }

    fn generate(
        &self,
        algorithm: i32,
    ) -> core::result::Result<GeneratedCredentialKey, CredentialKeyError> {
        if !self.supports_algorithm(algorithm) {
            return Err(CredentialKeyError::UnsupportedAlgorithm);
        }

        if !self.is_ready() {
            error!("TPM portable parent not provisioned");
            return Err(CredentialKeyError::TransientFailure(
                "TPM portable parent not provisioned".to_string(),
            ));
        }

        self.verify_tpm_capabilities()?;

        match algorithm {
            COSE_ALG_ES256 => self.generate_es256_key().map_err(|e| {
                error!("Failed to generate ES256 key: {:?}", e);
                CredentialKeyError::TransientFailure("Key generation failed".to_string())
            }),
            _ => Err(CredentialKeyError::UnsupportedAlgorithm),
        }
    }

    fn sign(
        &self,
        key: &CredentialKey,
        algorithm: i32,
        message: &[u8],
    ) -> core::result::Result<Vec<u8>, CredentialKeyError> {
        if key.provider.as_bytes() != parent::PROVIDER_ID {
            return Err(CredentialKeyError::UnsupportedProvider);
        }

        validate_record_version(key.format_version)?;

        if !self.supports_algorithm(algorithm) {
            return Err(CredentialKeyError::UnsupportedAlgorithm);
        }

        if !self.is_ready() {
            error!("TPM portable parent not provisioned");
            return Err(CredentialKeyError::TransientFailure(
                "TPM portable parent not provisioned".to_string(),
            ));
        }

        self.sign_with_tpm_key(key.material.as_slice(), message)
    }

    fn delete(&self, _key: &CredentialKey) -> core::result::Result<(), CredentialKeyError> {
        Ok(())
    }
}

pub fn compute_public_from_scalar(scalar: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    use p256::elliptic_curve::PrimeField;
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::{ProjectivePoint, Scalar};

    let field_bytes = p256::FieldBytes::try_from(scalar.as_slice()).map_err(|_| {
        error!("Failed to create FieldBytes from scalar");
        soft_fido2::Error::Other
    })?;
    let scalar_val = Scalar::from_repr(field_bytes)
        .into_option()
        .ok_or_else(|| {
            error!("Scalar is not valid for P-256");
            soft_fido2::Error::Other
        })?;

    let public_point = ProjectivePoint::GENERATOR * scalar_val;
    let affine = public_point.to_affine();
    let point = affine.to_sec1_point(false);

    let pub_x = point
        .x()
        .ok_or_else(|| {
            error!("Failed to extract x coordinate from public point");
            soft_fido2::Error::Other
        })?
        .to_vec();
    let pub_y = point
        .y()
        .ok_or_else(|| {
            error!("Failed to extract y coordinate from public point");
            soft_fido2::Error::Other
        })?
        .to_vec();

    Ok((pub_x, pub_y))
}

#[allow(dead_code)] // Used by integration tests via lib crate, not by the binary target
pub fn verify_public_key_matches(
    scalar: &[u8; 32],
    cose_public_key: &[u8],
) -> core::result::Result<bool, CredentialKeyError> {
    let (pub_x, pub_y) =
        compute_public_from_scalar(scalar).map_err(|_| CredentialKeyError::InvalidKeyMaterial)?;

    let mut expected = vec![0x04];
    expected.extend_from_slice(&pub_x);
    expected.extend_from_slice(&pub_y);

    Ok(expected == cose_public_key)
}

fn build_signing_key_public() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(false)
        .with_fixed_parent(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .map_err(|e| {
            error!("Failed to build signing key attributes: {}", e);
            soft_fido2::Error::Other
        })?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(|e| {
            error!("Failed to build signing key ECC parameters: {}", e);
            soft_fido2::Error::Other
        })?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| {
            error!("Failed to build signing key public: {}", e);
            soft_fido2::Error::Other
        })
}

/// Extract the COSE-encoded public key from a TPM public area
fn extract_cose_public_key(public: &Public) -> Result<Vec<u8>> {
    match public {
        Public::Ecc { unique, .. } => {
            let mut uncompressed = vec![0x04];
            let x = unique.x().value();
            let y = unique.y().value();

            let mut x_padded = vec![0u8; 32];
            let x_start = 32 - x.len();
            x_padded[x_start..].copy_from_slice(x);

            let mut y_padded = vec![0u8; 32];
            let y_start = 32 - y.len();
            y_padded[y_start..].copy_from_slice(y);

            uncompressed.extend_from_slice(&x_padded);
            uncompressed.extend_from_slice(&y_padded);

            Ok(uncompressed)
        }
        _ => {
            error!("Expected ECC public key");
            Err(soft_fido2::Error::Other)
        }
    }
}

/// Validate that a public template is suitable for signing
fn validate_signing_template(public: &Public) -> core::result::Result<(), CredentialKeyError> {
    match public {
        Public::Ecc { parameters, .. } => {
            if public.name_hashing_algorithm() != HashingAlgorithm::Sha256 {
                return Err(CredentialKeyError::InvalidKeyMaterial);
            }
            let attrs = public.object_attributes();
            if !attrs.sign_encrypt() {
                return Err(CredentialKeyError::InvalidKeyMaterial);
            }
            if attrs.restricted() {
                return Err(CredentialKeyError::InvalidKeyMaterial);
            }
            if attrs.fixed_tpm() {
                return Err(CredentialKeyError::InvalidKeyMaterial);
            }
            if attrs.fixed_parent() {
                return Err(CredentialKeyError::InvalidKeyMaterial);
            }
            if !attrs.user_with_auth() {
                return Err(CredentialKeyError::InvalidKeyMaterial);
            }
            if parameters.ecc_curve() != EccCurve::NistP256 {
                return Err(CredentialKeyError::InvalidKeyMaterial);
            }
            match parameters.ecc_scheme() {
                EccScheme::EcDsa(hash_scheme) => {
                    if hash_scheme.hashing_algorithm() != HashingAlgorithm::Sha256 {
                        return Err(CredentialKeyError::InvalidKeyMaterial);
                    }
                }
                _ => return Err(CredentialKeyError::InvalidKeyMaterial),
            }
            if parameters.symmetric_definition_object() != SymmetricDefinitionObject::Null {
                return Err(CredentialKeyError::InvalidKeyMaterial);
            }
            if parameters.key_derivation_function_scheme() != KeyDerivationFunctionScheme::Null {
                return Err(CredentialKeyError::InvalidKeyMaterial);
            }
            Ok(())
        }
        _ => Err(CredentialKeyError::InvalidKeyMaterial),
    }
}

/// Create a NULL HashcheckTicket
fn create_null_hashcheck_ticket() -> Result<tss_esapi::structures::HashcheckTicket> {
    use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
    use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;

    let ticket = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    };
    tss_esapi::structures::HashcheckTicket::try_from(ticket).map_err(|e| {
        error!("Failed to create null hashcheck ticket: {}", e);
        soft_fido2::Error::Other
    })
}

/// Convert a TPM ECDSA signature to DER format
fn signature_to_der(
    signature: &tss_esapi::structures::Signature,
) -> std::result::Result<Vec<u8>, CredentialKeyError> {
    match signature {
        tss_esapi::structures::Signature::EcDsa(ecdsa_sig) => {
            let r = ecdsa_sig.signature_r().value();
            let s = ecdsa_sig.signature_s().value();

            let r_der = encode_der_integer(r);
            let s_der = encode_der_integer(s);

            let mut der = Vec::new();
            let seq_len = r_der.len() + s_der.len();
            der.push(0x30);
            der.push(seq_len as u8);
            der.extend_from_slice(&r_der);
            der.extend_from_slice(&s_der);

            Ok(der)
        }
        _ => {
            error!("Expected ECDSA signature");
            Err(CredentialKeyError::TransientFailure(
                "Invalid signature type".to_string(),
            ))
        }
    }
}

/// Encode an integer as DER INTEGER
fn encode_der_integer(value: &[u8]) -> Vec<u8> {
    let mut der = Vec::new();
    der.push(0x02);

    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0 {
        start += 1;
    }

    let needs_padding = value[start] & 0x80 != 0;
    let len = value.len() - start + if needs_padding { 1 } else { 0 };

    der.push(len as u8);
    if needs_padding {
        der.push(0x00);
    }
    der.extend_from_slice(&value[start..]);

    der
}
