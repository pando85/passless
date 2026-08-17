//! Encrypted credential backup bundle support.
//!
//! Credential source material is serialized into a versioned portable format and
//! encrypted in-process. The client only ever sees the opaque encrypted bundle.
//! Wrapping keys are resolved by identifier from authenticator-local storage; key
//! bytes never cross the CTAP/client IPC boundary.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soft_fido2::{Credential, CredentialBackupState, Extensions, RelyingParty, User};
use soft_fido2_ctap::{CredentialKey, CredentialKeyProviderId, SecBytes};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub const CMD_PASSLESS_BACKUP: u8 = 0x43;
pub const CMD_PASSLESS_RESTORE: u8 = 0x44;
pub const BACKUP_PREPARE_SUBCOMMAND: u8 = 0x01;
pub const BACKUP_COMMIT_SUBCOMMAND: u8 = 0x02;
pub const MAX_BACKUP_BUNDLE_SIZE: usize = 64 * 1024;
pub const MAX_BACKUP_RECIPIENT_LENGTH: usize = 128;

const BACKUP_MAGIC: &str = "passless-credential-backup";
const BACKUP_FORMAT_VERSION: u16 = 2;
const PORTABLE_CREDENTIAL_VERSION: u16 = 1;
const CIPHER_SUITE: &str = "AES-256-GCM";
const AUTH_DOMAIN: &[u8] = b"passless-credential-backup-auth-v1";
const WRAPPING_KEY_DIR_ENV: &str = "PASSLESS_CREDENTIAL_BACKUP_KEY_DIR";
const WRAPPING_KEY_DIR_NAME: &str = "credential-backup-keys";
const WRAPPING_KEY_SUFFIX: &str = ".key";
const NONCE_SIZE: usize = 12;
const WRAPPING_KEY_SIZE: usize = 32;
const MAX_WRAPPING_KEY_FILE_SIZE: usize = 128;
const PASSLESS_AAGUID: [u8; 16] = [
    0x66, 0x69, 0x64, 0x6f, 0x2e, 0x70, 0x61, 0x73, 0x73, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x72, 0x73,
];

#[derive(Debug)]
pub enum BackupError {
    InvalidInput,
    InvalidBundle,
    UnsupportedCredential,
    CryptoUnavailable,
    CryptoFailed,
    TooLarge,
}

/// Authenticated, non-secret metadata carried outside the ciphertext.
#[derive(Debug, Serialize, Deserialize)]
struct CredentialBackupBundleV2 {
    magic: String,
    version: u16,
    cipher: String,
    recipient: String,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

#[derive(Serialize)]
struct AuthenticatedBundleMetadata<'a> {
    magic: &'a str,
    version: u16,
    cipher: &'a str,
    recipient: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
struct CredentialBackupEnvelopeV2 {
    magic: String,
    version: u16,
    source: SourceAuthenticatorMetadataV1,
    credential: PortableCredentialV1,
}

#[derive(Debug, Serialize, Deserialize)]
struct SourceAuthenticatorMetadataV1 {
    #[serde(with = "serde_bytes")]
    aaguid: Vec<u8>,
    firmware_version: String,
}

/// Stable credential-source schema independent of soft-fido2's `Credential`
/// serialization. Only software-provider key material is portable.
#[derive(Debug, Serialize, Deserialize)]
struct PortableCredentialV1 {
    version: u16,
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    rp_id: String,
    rp_name: Option<String>,
    #[serde(with = "serde_bytes")]
    user_id: Vec<u8>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    sign_count: u32,
    algorithm: i32,
    software_key_format_version: u16,
    private_key: SecBytes,
    created: i64,
    discoverable: bool,
    cred_protect: Option<u8>,
    #[serde(default)]
    hmac_secret: Option<bool>,
    cred_random: Option<SecBytes>,
    backup_eligible: bool,
    backed_up: bool,
}

impl PortableCredentialV1 {
    fn from_credential(credential: &Credential) -> Result<Self, BackupError> {
        ensure_exportable_credential(credential)?;
        Ok(Self {
            version: PORTABLE_CREDENTIAL_VERSION,
            id: credential.id.clone(),
            rp_id: credential.rp.id.clone(),
            rp_name: credential.rp.name.clone(),
            user_id: credential.user.id.clone(),
            user_name: credential.user.name.clone(),
            user_display_name: credential.user.display_name.clone(),
            sign_count: credential.sign_count,
            algorithm: credential.alg,
            software_key_format_version: credential.key.format_version,
            private_key: credential.key.material.clone(),
            created: credential.created,
            discoverable: credential.discoverable,
            cred_protect: credential.extensions.cred_protect,
            hmac_secret: credential.extensions.hmac_secret,
            cred_random: credential.extensions.cred_random.clone(),
            backup_eligible: credential.backup_state.is_eligible(),
            backed_up: credential.backup_state.is_backed_up(),
        })
    }

    fn into_credential(self) -> Result<Credential, BackupError> {
        self.validate()?;
        let backup_state = if self.backed_up {
            CredentialBackupState::BackedUp
        } else {
            CredentialBackupState::Eligible
        };
        Ok(Credential {
            id: self.id,
            rp: RelyingParty {
                id: self.rp_id,
                name: self.rp_name,
            },
            user: User {
                id: self.user_id,
                name: self.user_name,
                display_name: self.user_display_name,
            },
            sign_count: self.sign_count,
            alg: self.algorithm,
            key: CredentialKey::new(
                CredentialKeyProviderId::software(),
                self.software_key_format_version,
                self.private_key,
            ),
            created: self.created,
            discoverable: self.discoverable,
            backup_state,
            extensions: Extensions {
                cred_protect: self.cred_protect,
                hmac_secret: self.hmac_secret,
                cred_random: self.cred_random,
            },
        })
    }

    fn validate(&self) -> Result<(), BackupError> {
        if self.version != PORTABLE_CREDENTIAL_VERSION
            || self.id.is_empty()
            || self.id.len() > 64
            || self.rp_id.is_empty()
            || self.rp_id.len() > 253
            || self.user_id.is_empty()
            || self.user_id.len() > 64
            || self.software_key_format_version != 1
            || self.private_key.as_slice().len() != 32
            || !self.backup_eligible
        {
            return Err(BackupError::InvalidBundle);
        }
        if let Some(cred_protect) = self.cred_protect
            && !(1..=3).contains(&cred_protect)
        {
            return Err(BackupError::InvalidBundle);
        }
        if let Some(cred_random) = &self.cred_random
            && cred_random.as_slice().len() != 32
        {
            return Err(BackupError::InvalidBundle);
        }
        Ok(())
    }
}

pub fn encrypt_credential(
    credential: &Credential,
    recipient: &str,
) -> Result<Vec<u8>, BackupError> {
    validate_recipient(recipient)?;
    let wrapping_key = load_wrapping_key(recipient)?;
    encrypt_credential_with_key(credential, recipient, &wrapping_key)
}

pub fn decrypt_credential(bundle: &[u8]) -> Result<Credential, BackupError> {
    let outer = decode_bundle(bundle)?;
    let wrapping_key = load_wrapping_key(&outer.recipient)?;
    decrypt_bundle_with_key(outer, &wrapping_key)
}

fn encrypt_credential_with_key(
    credential: &Credential,
    recipient: &str,
    wrapping_key: &[u8; WRAPPING_KEY_SIZE],
) -> Result<Vec<u8>, BackupError> {
    validate_recipient(recipient)?;
    let portable = PortableCredentialV1::from_credential(credential)?;
    let envelope = CredentialBackupEnvelopeV2 {
        magic: BACKUP_MAGIC.to_string(),
        version: BACKUP_FORMAT_VERSION,
        source: SourceAuthenticatorMetadataV1 {
            aaguid: PASSLESS_AAGUID.to_vec(),
            firmware_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        credential: portable,
    };
    let plaintext =
        Zeroizing::new(serde_cbor::to_vec(&envelope).map_err(|_| BackupError::InvalidBundle)?);
    if plaintext.len() > MAX_BACKUP_BUNDLE_SIZE {
        return Err(BackupError::TooLarge);
    }

    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| BackupError::CryptoFailed)?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let aad = authenticated_metadata(recipient)?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| BackupError::CryptoFailed)?;

    let outer = CredentialBackupBundleV2 {
        magic: BACKUP_MAGIC.to_string(),
        version: BACKUP_FORMAT_VERSION,
        cipher: CIPHER_SUITE.to_string(),
        recipient: recipient.to_string(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };
    let bundle = serde_cbor::to_vec(&outer).map_err(|_| BackupError::InvalidBundle)?;
    if bundle.is_empty() || bundle.len() > MAX_BACKUP_BUNDLE_SIZE {
        return Err(BackupError::TooLarge);
    }
    Ok(bundle)
}

fn decrypt_bundle_with_key(
    outer: CredentialBackupBundleV2,
    wrapping_key: &[u8; WRAPPING_KEY_SIZE],
) -> Result<Credential, BackupError> {
    let nonce_bytes: [u8; NONCE_SIZE] = outer
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| BackupError::InvalidBundle)?;
    let nonce = Nonce::from(nonce_bytes);
    let aad = authenticated_metadata(&outer.recipient)?;
    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| BackupError::CryptoFailed)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &outer.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| BackupError::CryptoFailed)?,
    );

    let envelope: CredentialBackupEnvelopeV2 =
        serde_cbor::from_slice(&plaintext).map_err(|_| BackupError::InvalidBundle)?;
    validate_envelope(&envelope)?;
    envelope.credential.into_credential()
}

fn decode_bundle(bundle: &[u8]) -> Result<CredentialBackupBundleV2, BackupError> {
    if bundle.is_empty() || bundle.len() > MAX_BACKUP_BUNDLE_SIZE {
        return Err(BackupError::TooLarge);
    }
    let outer: CredentialBackupBundleV2 =
        serde_cbor::from_slice(bundle).map_err(|_| BackupError::InvalidBundle)?;
    if outer.magic != BACKUP_MAGIC
        || outer.version != BACKUP_FORMAT_VERSION
        || outer.cipher != CIPHER_SUITE
        || outer.nonce.len() != NONCE_SIZE
        || outer.ciphertext.is_empty()
    {
        return Err(BackupError::InvalidBundle);
    }
    validate_recipient(&outer.recipient).map_err(|_| BackupError::InvalidBundle)?;
    Ok(outer)
}

fn validate_envelope(envelope: &CredentialBackupEnvelopeV2) -> Result<(), BackupError> {
    if envelope.magic != BACKUP_MAGIC
        || envelope.version != BACKUP_FORMAT_VERSION
        || envelope.source.aaguid.len() != PASSLESS_AAGUID.len()
        || envelope.source.firmware_version.is_empty()
    {
        return Err(BackupError::InvalidBundle);
    }
    envelope.credential.validate()
}

fn authenticated_metadata(recipient: &str) -> Result<Vec<u8>, BackupError> {
    serde_cbor::to_vec(&AuthenticatedBundleMetadata {
        magic: BACKUP_MAGIC,
        version: BACKUP_FORMAT_VERSION,
        cipher: CIPHER_SUITE,
        recipient,
    })
    .map_err(|_| BackupError::InvalidBundle)
}

fn wrapping_key_dir() -> Result<PathBuf, BackupError> {
    if let Some(path) = std::env::var_os(WRAPPING_KEY_DIR_ENV) {
        if path.is_empty() {
            return Err(BackupError::CryptoUnavailable);
        }
        return Ok(PathBuf::from(path));
    }
    dirs::config_dir()
        .map(|path| path.join("passless").join(WRAPPING_KEY_DIR_NAME))
        .ok_or(BackupError::CryptoUnavailable)
}

fn load_wrapping_key(recipient: &str) -> Result<Zeroizing<[u8; WRAPPING_KEY_SIZE]>, BackupError> {
    validate_recipient(recipient)?;
    let path = wrapping_key_dir()?.join(format!("{recipient}{WRAPPING_KEY_SUFFIX}"));
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| BackupError::CryptoUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| BackupError::CryptoUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BackupError::InvalidInput);
    }

    let mut contents = Zeroizing::new(Vec::new());
    file.take((MAX_WRAPPING_KEY_FILE_SIZE + 1) as u64)
        .read_to_end(&mut contents)
        .map_err(|_| BackupError::CryptoUnavailable)?;
    if contents.len() > MAX_WRAPPING_KEY_FILE_SIZE {
        return Err(BackupError::InvalidInput);
    }
    parse_wrapping_key(&contents)
}

fn parse_wrapping_key(data: &[u8]) -> Result<Zeroizing<[u8; WRAPPING_KEY_SIZE]>, BackupError> {
    let mut key = [0u8; WRAPPING_KEY_SIZE];
    if data.len() == WRAPPING_KEY_SIZE {
        key.copy_from_slice(data);
        return Ok(Zeroizing::new(key));
    }

    let text = std::str::from_utf8(data)
        .map_err(|_| BackupError::InvalidInput)?
        .trim();
    if text.len() != WRAPPING_KEY_SIZE * 2 {
        return Err(BackupError::InvalidInput);
    }
    let decoded = Zeroizing::new(hex::decode(text).map_err(|_| BackupError::InvalidInput)?);
    if decoded.len() != WRAPPING_KEY_SIZE {
        return Err(BackupError::InvalidInput);
    }
    key.copy_from_slice(&decoded);
    Ok(Zeroizing::new(key))
}

pub fn bundle_token(bundle: &[u8]) -> [u8; 32] {
    Sha256::digest(bundle).into()
}

pub fn backup_prepare_auth_data(credential_id: &[u8], recipient: &str) -> [u8; 32] {
    hash_auth_data(
        CMD_PASSLESS_BACKUP,
        BACKUP_PREPARE_SUBCOMMAND,
        &[credential_id, recipient.as_bytes()],
    )
}

pub fn backup_commit_auth_data(credential_id: &[u8], token: &[u8]) -> [u8; 32] {
    hash_auth_data(
        CMD_PASSLESS_BACKUP,
        BACKUP_COMMIT_SUBCOMMAND,
        &[credential_id, token],
    )
}

pub fn restore_auth_data(bundle: &[u8], replace: bool) -> [u8; 32] {
    let replace_byte = [u8::from(replace)];
    hash_auth_data(CMD_PASSLESS_RESTORE, 0, &[bundle, &replace_byte])
}

fn hash_auth_data(command: u8, subcommand: u8, fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTH_DOMAIN);
    hasher.update([command, subcommand]);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn validate_recipient(recipient: &str) -> Result<(), BackupError> {
    if recipient.is_empty()
        || recipient.len() > MAX_BACKUP_RECIPIENT_LENGTH
        || recipient == "."
        || recipient == ".."
        || recipient.contains("..")
        || !recipient
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'_' | b'-' | b'+'))
    {
        return Err(BackupError::InvalidInput);
    }
    Ok(())
}

fn ensure_exportable_credential(credential: &Credential) -> Result<(), BackupError> {
    if !credential.key.provider.is_software()
        || credential.key.format_version != 1
        || credential.key.material.as_slice().len() != 32
        || !credential.backup_state.is_eligible()
    {
        return Err(BackupError::UnsupportedCredential);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(state: CredentialBackupState) -> Credential {
        Credential {
            id: vec![1, 2, 3],
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
            },
            user: User {
                id: vec![4, 5, 6],
                name: Some("alice".to_string()),
                display_name: Some("Alice".to_string()),
            },
            sign_count: 7,
            alg: -7,
            key: CredentialKey::software(SecBytes::from_slice(&[0x9d; 32])),
            created: 123,
            discoverable: true,
            backup_state: state,
            extensions: Extensions {
                cred_protect: Some(3),
                hmac_secret: Some(true),
                cred_random: Some(SecBytes::from_slice(&[0x4a; 32])),
            },
        }
    }

    fn test_key(byte: u8) -> [u8; WRAPPING_KEY_SIZE] {
        [byte; WRAPPING_KEY_SIZE]
    }

    #[test]
    fn encrypted_round_trip_preserves_complete_credential_source() {
        let original = credential(CredentialBackupState::BackedUp);
        let bundle =
            encrypt_credential_with_key(&original, "backup-main", &test_key(0x11)).unwrap();
        let outer = decode_bundle(&bundle).unwrap();
        assert_eq!(outer.recipient, "backup-main");
        assert_eq!(outer.version, BACKUP_FORMAT_VERSION);
        assert_eq!(outer.cipher, CIPHER_SUITE);

        let restored = decrypt_bundle_with_key(outer, &test_key(0x11)).unwrap();
        assert_eq!(restored, original);
        assert_eq!(restored.backup_state, CredentialBackupState::BackedUp);
        assert_eq!(restored.extensions.cred_protect, Some(3));
        assert_eq!(
            restored
                .extensions
                .cred_random
                .as_ref()
                .map(SecBytes::as_slice),
            Some([0x4a; 32].as_slice())
        );
    }

    #[test]
    fn round_trip_preserves_hmac_secret_state_independently_of_cred_random() {
        let mut original = credential(CredentialBackupState::BackedUp);
        original.extensions.hmac_secret = None;
        assert!(original.extensions.cred_random.is_some());

        let bundle =
            encrypt_credential_with_key(&original, "backup-main", &test_key(0x12)).unwrap();
        let outer = decode_bundle(&bundle).unwrap();
        let restored = decrypt_bundle_with_key(outer, &test_key(0x12)).unwrap();

        assert_eq!(restored.extensions.hmac_secret, None);
        assert!(restored.extensions.cred_random.is_some());
        assert_eq!(restored, original);
    }

    #[test]
    fn bundle_does_not_expose_private_key_plaintext() {
        let original = credential(CredentialBackupState::BackedUp);
        let bundle =
            encrypt_credential_with_key(&original, "backup-main", &test_key(0x22)).unwrap();
        assert!(!bundle.windows(32).any(|window| window == [0x9d; 32]));
        assert!(!bundle.windows(32).any(|window| window == [0x4a; 32]));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let original = credential(CredentialBackupState::BackedUp);
        let bundle =
            encrypt_credential_with_key(&original, "backup-main", &test_key(0x33)).unwrap();
        let mut outer = decode_bundle(&bundle).unwrap();
        outer.ciphertext[0] ^= 0x80;
        assert!(matches!(
            decrypt_bundle_with_key(outer, &test_key(0x33)),
            Err(BackupError::CryptoFailed)
        ));
    }

    #[test]
    fn wrong_wrapping_key_is_rejected() {
        let original = credential(CredentialBackupState::BackedUp);
        let bundle =
            encrypt_credential_with_key(&original, "backup-main", &test_key(0x44)).unwrap();
        let outer = decode_bundle(&bundle).unwrap();
        assert!(matches!(
            decrypt_bundle_with_key(outer, &test_key(0x45)),
            Err(BackupError::CryptoFailed)
        ));
    }

    #[test]
    fn recipient_metadata_is_authenticated() {
        let original = credential(CredentialBackupState::BackedUp);
        let bundle =
            encrypt_credential_with_key(&original, "backup-main", &test_key(0x55)).unwrap();
        let mut outer = decode_bundle(&bundle).unwrap();
        outer.recipient = "backup-other".to_string();
        assert!(matches!(
            decrypt_bundle_with_key(outer, &test_key(0x55)),
            Err(BackupError::CryptoFailed)
        ));
    }

    #[test]
    fn non_backup_eligible_credential_is_not_exportable() {
        let original = credential(CredentialBackupState::NotEligible);
        assert!(matches!(
            encrypt_credential_with_key(&original, "backup-main", &test_key(0x66)),
            Err(BackupError::UnsupportedCredential)
        ));
    }

    #[test]
    fn handler_must_check_backup_eligibility_before_mutating_state() {
        let original = credential(CredentialBackupState::NotEligible);
        assert!(!original.backup_state.is_eligible());

        let mut mutated = original.clone();
        mutated.backup_state = CredentialBackupState::BackedUp;
        let portable = PortableCredentialV1::from_credential(&mutated).unwrap();
        assert!(portable.backup_eligible);

        let portable_from_original = PortableCredentialV1::from_credential(&original);
        assert!(matches!(
            portable_from_original,
            Err(BackupError::UnsupportedCredential)
        ));
    }

    #[test]
    fn eligible_state_remains_eligible_in_portable_source() {
        let original = credential(CredentialBackupState::Eligible);
        let bundle =
            encrypt_credential_with_key(&original, "backup-main", &test_key(0x77)).unwrap();
        let outer = decode_bundle(&bundle).unwrap();
        let restored = decrypt_bundle_with_key(outer, &test_key(0x77)).unwrap();
        assert_eq!(restored.backup_state, CredentialBackupState::Eligible);
    }

    #[test]
    fn legacy_openpgp_bundle_is_rejected_safely() {
        let legacy_packet = [0x85, 0x01, 0x02, 0x03, 0x04];
        assert!(matches!(
            decode_bundle(&legacy_packet),
            Err(BackupError::InvalidBundle)
        ));
    }

    #[test]
    fn wrapping_key_parser_accepts_raw_and_hex_keys() {
        let raw = [0xa5; WRAPPING_KEY_SIZE];
        assert_eq!(&*parse_wrapping_key(&raw).unwrap(), &raw);

        let hex_key = format!("{}\n", hex::encode(raw));
        assert_eq!(&*parse_wrapping_key(hex_key.as_bytes()).unwrap(), &raw);
    }

    #[test]
    fn wrapping_key_parser_rejects_wrong_size() {
        assert!(matches!(
            parse_wrapping_key(b"too-short"),
            Err(BackupError::InvalidInput)
        ));
    }

    #[test]
    fn request_authentication_binds_all_inputs() {
        assert_ne!(
            backup_prepare_auth_data(&[1], "backup-main"),
            backup_prepare_auth_data(&[2], "backup-main")
        );
        assert_ne!(
            backup_prepare_auth_data(&[1], "backup-main"),
            backup_prepare_auth_data(&[1], "backup-other")
        );
        assert_ne!(
            restore_auth_data(b"bundle", false),
            restore_auth_data(b"bundle", true)
        );
    }

    #[test]
    fn rejects_invalid_recipient() {
        for recipient in ["", "../secret", "a/b", "..", "bad recipient"] {
            assert!(matches!(
                validate_recipient(recipient),
                Err(BackupError::InvalidInput)
            ));
        }
        assert!(matches!(
            validate_recipient(&"x".repeat(MAX_BACKUP_RECIPIENT_LENGTH + 1)),
            Err(BackupError::InvalidInput)
        ));
    }
}
