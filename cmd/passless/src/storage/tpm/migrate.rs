use crate::storage::index::load_credential_paths;
use crate::storage::tpm::TpmStorageAdapter;
use crate::storage::tpm::portable::TpmCredentialKeyProvider;
use crate::storage::tpm::portable::provider::compute_public_from_scalar;

use soft_fido2_ctap::key_provider::CredentialKeyProvider;

use std::path::{Path, PathBuf};

use log::{debug, info};
use zeroize::Zeroizing;

use passless_core::config::tpm_path;
use passless_core::{Error, Result};

const COSE_ALG_ES256: i32 = -7;

#[derive(Debug, Default)]
pub struct MigrationReport {
    pub migrated: Vec<String>,
    pub skipped: Vec<(String, String)>,
    pub failed: Vec<(String, String)>,
}

impl MigrationReport {
    pub fn already_portable_count(&self) -> usize {
        self.skipped
            .iter()
            .filter(|(_, r)| r == "already portable")
            .count()
    }

    pub fn non_es256_skip_count(&self) -> usize {
        self.skipped
            .iter()
            .filter(|(_, r)| r != "already portable")
            .count()
    }
}

pub fn migrate_credentials(
    credential_id: Option<String>,
    all: bool,
    dry_run: bool,
    backup_dir: Option<String>,
    path: Option<String>,
    tcti: Option<String>,
) -> Result<MigrationReport> {
    let storage_dir = PathBuf::from(path.as_deref().unwrap_or(&tpm_path()));
    let tcti_str = tcti.or_else(|| Some("device:/dev/tpmrm0".to_string()));

    if !storage_dir.exists() {
        return Err(Error::Other(format!(
            "TPM storage directory does not exist: {}",
            storage_dir.display()
        )));
    }

    let portable_parent_path = storage_dir.join("portable_parent.json");
    if !portable_parent_path.exists() {
        return Err(Error::Other(
            "TPM portable parent is not provisioned. \
             Run 'passless tpm provision' before migrating."
                .to_string(),
        ));
    }

    let target_cred_id = if let Some(ref hex_id) = credential_id {
        Some(
            hex::decode(hex_id)
                .map_err(|e| Error::Other(format!("Invalid credential ID hex: {}", e)))?,
        )
    } else {
        None
    };

    let cred_paths = load_credential_paths(&storage_dir, "tpm")
        .map_err(|e| Error::Other(format!("Failed to scan credentials: {}", e)))?;

    let legacy_adapter =
        TpmStorageAdapter::new_with_options(storage_dir.clone(), tcti_str.clone(), true)
            .map_err(|_| Error::Other("Failed to create legacy TPM adapter".to_string()))?;

    let mut report = MigrationReport::default();

    let candidate_paths: Vec<PathBuf> = if let Some(ref cred_id) = target_cred_id {
        cred_paths
            .id
            .values()
            .filter(|p| p.cred_id == *cred_id)
            .map(|p| p.to_path(&storage_dir))
            .collect()
    } else if all {
        cred_paths
            .id
            .values()
            .map(|p| p.to_path(&storage_dir))
            .collect()
    } else {
        Vec::new()
    };

    for cred_path in &candidate_paths {
        let cred_id_hex = cred_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_string();

        let cred = match legacy_adapter.read_credential_from_path_no_cache(cred_path) {
            Ok(c) => c,
            Err(_) => {
                debug!(
                    "Skipping {} (cannot unseal with legacy adapter, likely already portable)",
                    cred_id_hex
                );
                report
                    .skipped
                    .push((cred_id_hex, "already portable".to_string()));
                continue;
            }
        };

        if !cred.key.provider.is_software() {
            debug!("Skipping {} (already has key provider)", cred_id_hex);
            report
                .skipped
                .push((cred_id_hex, "already portable".to_string()));
            continue;
        }

        if cred.alg != COSE_ALG_ES256 {
            let reason = format!("not migratable (algorithm {} != ES256)", cred.alg);
            report.skipped.push((cred_id_hex, reason));
            continue;
        }

        let scalar_bytes = cred.key.material.as_slice();
        if scalar_bytes.len() != 32 {
            let reason = format!(
                "not migratable (private key is {} bytes, expected 32)",
                scalar_bytes.len()
            );
            report.skipped.push((cred_id_hex, reason));
            continue;
        }

        if dry_run {
            report.migrated.push(cred_id_hex);
            continue;
        }

        match migrate_one(&storage_dir, &tcti_str, cred_path, &cred, &backup_dir) {
            Ok(()) => {
                info!("Migrated credential {}", hex::encode(&cred.id));
                report.migrated.push(cred_id_hex);
            }
            Err(e) => {
                let reason = format!("migration failed: {}", e);
                report.failed.push((cred_id_hex, reason));
            }
        }
    }

    Ok(report)
}

fn migrate_one(
    storage_dir: &Path,
    tcti: &Option<String>,
    cred_path: &Path,
    cred: &soft_fido2::Credential,
    backup_dir: &Option<String>,
) -> Result<()> {
    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(cred.key.material.as_slice());

    let (pub_x, pub_y) = compute_public_from_scalar(&scalar)
        .map_err(|_| Error::Other("Failed to compute public key from scalar".to_string()))?;

    let mut expected_cose = vec![0x04];
    expected_cose.extend_from_slice(&pub_x);
    expected_cose.extend_from_slice(&pub_y);

    let provider = TpmCredentialKeyProvider::new(storage_dir.to_path_buf(), tcti.clone())
        .map_err(|_| Error::Other("Failed to create TPM key provider".to_string()))?;

    let imported = provider
        .import_existing_es256_key(&scalar)
        .map_err(|e| Error::Other(format!("Failed to import ES256 key into TPM: {:?}", e)))?;

    if imported.cose_public_key != expected_cose {
        return Err(Error::Other(
            "Imported TPM public key does not match recomputed public key".to_string(),
        ));
    }

    let test_message = b"passless-migrate-self-test";
    let signature = provider
        .sign(&imported.key, COSE_ALG_ES256, test_message)
        .map_err(|e| Error::Other(format!("Self-test signing failed: {:?}", e)))?;

    verify_signature_with_public(&imported.cose_public_key, test_message, &signature)?;

    let backup_path = resolve_backup_dir(storage_dir, backup_dir);
    std::fs::create_dir_all(&backup_path).map_err(|e| {
        Error::Other(format!(
            "Failed to create backup directory {}: {}",
            backup_path.display(),
            e
        ))
    })?;

    let rel = cred_path
        .strip_prefix(storage_dir)
        .map_err(|_| Error::Other("Credential path not under storage dir".to_string()))?;
    let backup_file = backup_path.join(rel);
    if let Some(backup_parent) = backup_file.parent() {
        std::fs::create_dir_all(backup_parent)
            .map_err(|e| Error::Other(format!("Failed to create backup subdirectory: {}", e)))?;
    }
    std::fs::copy(cred_path, &backup_file)
        .map_err(|e| Error::Other(format!("Failed to backup legacy record: {}", e)))?;
    info!("Backed up legacy record to {}", backup_file.display());

    let migrated_cred = soft_fido2::Credential {
        id: cred.id.clone(),
        rp: cred.rp.clone(),
        user: cred.user.clone(),
        sign_count: cred.sign_count,
        alg: cred.alg,
        key: imported.key,
        created: cred.created,
        discoverable: cred.discoverable,
        extensions: cred.extensions.clone(),
        backup_state: soft_fido2::CredentialBackupState::NotEligible,
    };

    let mut portable_adapter =
        TpmStorageAdapter::new_portable(storage_dir.to_path_buf(), tcti.clone(), true).map_err(
            |_| Error::Other("Failed to create portable TPM adapter for writing".to_string()),
        )?;

    portable_adapter
        .write_credential(&migrated_cred)
        .map_err(|e| Error::Other(format!("Failed to write portable record: {:?}", e)))?;

    Ok(())
}

fn verify_signature_with_public(
    cose_public_key: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<()> {
    use p256::PublicKey;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    let public_key = PublicKey::from_sec1_bytes(cose_public_key)
        .map_err(|e| Error::Other(format!("Failed to parse COSE public key: {}", e)))?;
    let verifying_key = VerifyingKey::from(&public_key);
    let sig = Signature::from_der(signature_der)
        .map_err(|e| Error::Other(format!("Failed to parse DER signature: {}", e)))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|e| Error::Other(format!("Self-test signature verification failed: {}", e)))?;

    Ok(())
}

fn resolve_backup_dir(storage_dir: &Path, backup_dir: &Option<String>) -> PathBuf {
    if let Some(dir) = backup_dir {
        PathBuf::from(dir)
    } else {
        storage_dir.join(".backup")
    }
}
