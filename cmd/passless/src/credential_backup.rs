//! Encrypted credential backup bundle support.
//!
//! Plaintext credential material is serialized and encrypted only inside the
//! authenticator process. The client sees an opaque OpenPGP ciphertext.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soft_fido2::Credential;
use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub const CMD_PASSLESS_BACKUP: u8 = 0x43;
pub const CMD_PASSLESS_RESTORE: u8 = 0x44;
pub const BACKUP_PREPARE_SUBCOMMAND: u8 = 0x01;
pub const BACKUP_COMMIT_SUBCOMMAND: u8 = 0x02;
pub const MAX_BACKUP_BUNDLE_SIZE: usize = 64 * 1024;
pub const MAX_BACKUP_RECIPIENT_LENGTH: usize = 512;

const BACKUP_MAGIC: &str = "passless-credential-backup";
const BACKUP_FORMAT_VERSION: u16 = 1;
const AUTH_DOMAIN: &[u8] = b"passless-credential-backup-auth-v1";

#[derive(Debug)]
pub enum BackupError {
    InvalidInput,
    InvalidBundle,
    UnsupportedCredential,
    CryptoUnavailable,
    CryptoFailed,
    TooLarge,
}

#[derive(Serialize, Deserialize)]
struct CredentialBackupEnvelope {
    magic: String,
    version: u16,
    credential: Credential,
}

pub fn encrypt_credential(
    credential: &Credential,
    recipient: &str,
) -> Result<Vec<u8>, BackupError> {
    validate_recipient(recipient)?;
    ensure_software_credential(credential)?;

    let envelope = CredentialBackupEnvelope {
        magic: BACKUP_MAGIC.to_string(),
        version: BACKUP_FORMAT_VERSION,
        credential: credential.clone(),
    };
    let plaintext =
        Zeroizing::new(serde_cbor::to_vec(&envelope).map_err(|_| BackupError::InvalidBundle)?);

    let mut child = Command::new("gpg")
        .args([
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--compress-algo",
            "none",
            "--encrypt",
            "--recipient",
            recipient,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| BackupError::CryptoUnavailable)?;

    child
        .stdin
        .take()
        .ok_or(BackupError::CryptoFailed)?
        .write_all(&plaintext)
        .map_err(|_| BackupError::CryptoFailed)?;

    let output = child
        .wait_with_output()
        .map_err(|_| BackupError::CryptoFailed)?;
    if !output.status.success() {
        return Err(BackupError::CryptoFailed);
    }
    if output.stdout.is_empty() || output.stdout.len() > MAX_BACKUP_BUNDLE_SIZE {
        return Err(BackupError::TooLarge);
    }

    Ok(output.stdout)
}

pub fn decrypt_credential(bundle: &[u8]) -> Result<Credential, BackupError> {
    if bundle.is_empty() || bundle.len() > MAX_BACKUP_BUNDLE_SIZE {
        return Err(BackupError::TooLarge);
    }

    let mut child = Command::new("gpg")
        .args(["--batch", "--decrypt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| BackupError::CryptoUnavailable)?;

    child
        .stdin
        .take()
        .ok_or(BackupError::CryptoFailed)?
        .write_all(bundle)
        .map_err(|_| BackupError::CryptoFailed)?;

    let output = child
        .wait_with_output()
        .map_err(|_| BackupError::CryptoFailed)?;
    if !output.status.success() || output.stdout.len() > MAX_BACKUP_BUNDLE_SIZE {
        return Err(BackupError::CryptoFailed);
    }

    let plaintext = Zeroizing::new(output.stdout);
    let envelope: CredentialBackupEnvelope =
        serde_cbor::from_slice(&plaintext).map_err(|_| BackupError::InvalidBundle)?;
    if envelope.magic != BACKUP_MAGIC || envelope.version != BACKUP_FORMAT_VERSION {
        return Err(BackupError::InvalidBundle);
    }
    ensure_software_credential(&envelope.credential)?;
    Ok(envelope.credential)
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
    if recipient.trim().is_empty()
        || recipient.len() > MAX_BACKUP_RECIPIENT_LENGTH
        || recipient.contains('\0')
    {
        return Err(BackupError::InvalidInput);
    }
    Ok(())
}

fn ensure_software_credential(credential: &Credential) -> Result<(), BackupError> {
    if !credential.key.provider.is_software() {
        return Err(BackupError::UnsupportedCredential);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soft_fido2::{CredentialBackupState, Extensions, RelyingParty, User};
    use soft_fido2_ctap::{CredentialKey, SecBytes};

    fn credential() -> Credential {
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
            key: CredentialKey::software(SecBytes::from_slice(&[9; 32])),
            created: 123,
            discoverable: true,
            backup_state: CredentialBackupState::BackedUp,
            extensions: Extensions::default(),
        }
    }

    #[test]
    fn envelope_round_trip_preserves_backup_state() {
        let original = credential();
        let plaintext = serde_cbor::to_vec(&CredentialBackupEnvelope {
            magic: BACKUP_MAGIC.to_string(),
            version: BACKUP_FORMAT_VERSION,
            credential: original.clone(),
        })
        .unwrap();
        let decoded: CredentialBackupEnvelope = serde_cbor::from_slice(&plaintext).unwrap();
        assert_eq!(decoded.credential, original);
        assert_eq!(
            decoded.credential.backup_state,
            CredentialBackupState::BackedUp
        );
    }

    #[test]
    fn request_authentication_binds_all_inputs() {
        assert_ne!(
            backup_prepare_auth_data(&[1], "alice@example.com"),
            backup_prepare_auth_data(&[2], "alice@example.com")
        );
        assert_ne!(
            backup_prepare_auth_data(&[1], "alice@example.com"),
            backup_prepare_auth_data(&[1], "bob@example.com")
        );
        assert_ne!(
            restore_auth_data(b"bundle", false),
            restore_auth_data(b"bundle", true)
        );
    }

    #[test]
    fn rejects_invalid_recipient() {
        assert!(matches!(
            validate_recipient(""),
            Err(BackupError::InvalidInput)
        ));
        assert!(matches!(
            validate_recipient(&"x".repeat(MAX_BACKUP_RECIPIENT_LENGTH + 1)),
            Err(BackupError::InvalidInput)
        ));
    }
}
