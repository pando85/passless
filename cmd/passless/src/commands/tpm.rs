//! TPM portable parent management commands

use passless_core::Result;
use passless_core::config::{TpmAction, tpm_path};

use crate::storage::tpm::portable::PortableParent;
use crate::storage::tpm::portable::provision::{parse_hex_seed, resolve_seed};

use std::path::PathBuf;

use log::info;
use zeroize::Zeroizing;

fn resolve_path(path: Option<String>) -> PathBuf {
    PathBuf::from(path.unwrap_or_else(tpm_path))
}

fn resolve_tcti(tcti: Option<String>) -> Option<String> {
    tcti.or_else(|| Some("device:/dev/tpmrm0".to_string()))
}

/// Dispatch TPM subcommands
pub fn dispatch(action: &TpmAction) -> Result<()> {
    match action {
        TpmAction::Provision {
            generate,
            seed_file,
            seed_stdin,
            path,
            tcti,
        } => provision(
            *generate,
            seed_file.clone(),
            *seed_stdin,
            path.clone(),
            tcti.clone(),
        ),
        TpmAction::Status { path, tcti } => status(path.clone(), tcti.clone()),
        TpmAction::Remove {
            confirm,
            path,
            tcti,
        } => remove(*confirm, path.clone(), tcti.clone()),
        TpmAction::Migrate {
            credential_id,
            all,
            dry_run,
            backup_dir,
            path,
            tcti,
        } => super::tpm_migrate::migrate(
            credential_id.clone(),
            *all,
            *dry_run,
            backup_dir.clone(),
            path.clone(),
            tcti.clone(),
        ),
    }
}

fn provision(
    generate: bool,
    seed_file: Option<PathBuf>,
    seed_stdin: bool,
    path: Option<String>,
    tcti: Option<String>,
) -> Result<()> {
    let storage_dir = resolve_path(path);
    let tcti = resolve_tcti(tcti);

    std::fs::create_dir_all(&storage_dir).map_err(|e| {
        passless_core::Error::Other(format!(
            "Failed to create storage directory {}: {}",
            storage_dir.display(),
            e
        ))
    })?;

    let parent = PortableParent::new(storage_dir.clone(), tcti)?;

    if parent.is_provisioned() {
        return Err(passless_core::Error::Other(
            "TPM portable parent is already provisioned. \
             Run 'passless tpm remove --confirm' first to re-provision."
                .to_string(),
        ));
    }

    let seed: Zeroizing<Vec<u8>> = if generate || seed_file.is_some() || seed_stdin {
        let resolved = resolve_seed(generate, seed_file.as_deref(), seed_stdin)?;
        if generate {
            let hex_seed = hex::encode(resolved.as_slice());
            eprintln!("=== RECOVERY SEED (back this up securely!) ===");
            eprintln!("{}", hex_seed);
            eprintln!("=== END RECOVERY SEED ===");
            eprintln!("WARNING: This is the ONLY time the seed will be shown.");
            eprintln!("Store it offline. Anyone with this seed can clone your credentials.");
        }
        resolved
    } else {
        eprint!("Enter recovery seed (64 hex chars): ");
        let hex_str = rpassword::read_password()
            .map_err(|e| passless_core::Error::Other(format!("Failed to read seed: {}", e)))?;
        parse_hex_seed(&hex_str)?
    };

    parent.provision(&seed)?;

    let metadata = parent.load_metadata()?;
    info!(
        "Portable parent provisioned at persistent handle 0x{:08X}",
        metadata.persistent_handle
    );
    println!("TPM portable parent provisioned successfully.");
    println!("Persistent handle: 0x{:08X}", metadata.persistent_handle);
    eprintln!("NOTE: Portable keys use an empty TPM authValue (pre-1.0 limitation).");
    eprintln!("Security relies on seed secrecy and TPM sealing. See docs/TPM_PORTABLE.md.");

    Ok(())
}

fn status(path: Option<String>, tcti: Option<String>) -> Result<()> {
    let storage_dir = resolve_path(path);
    let tcti = resolve_tcti(tcti);

    let parent = PortableParent::new(storage_dir, tcti)?;

    if !parent.is_provisioned() {
        println!("Status: not provisioned");
        return Ok(());
    }

    let metadata = parent.load_metadata()?;
    parent.verify_parent(&metadata)?;

    println!("Status: OK");
    println!("Version: {}", metadata.version);
    println!("Persistent handle: 0x{:08X}", metadata.persistent_handle);
    println!("Parent name: {}", hex::encode(&metadata.parent_name));

    Ok(())
}

fn remove(confirm: bool, path: Option<String>, tcti: Option<String>) -> Result<()> {
    if !confirm {
        return Err(passless_core::Error::Other(
            "Removal requires --confirm flag".to_string(),
        ));
    }

    let storage_dir = resolve_path(path);
    let tcti = resolve_tcti(tcti);

    let parent = PortableParent::new(storage_dir.clone(), tcti)?;

    if !parent.is_provisioned() {
        println!("Already not provisioned.");
        return Ok(());
    }

    let metadata = parent.load_metadata()?;
    parent.remove()?;

    let metadata_path = storage_dir.join("portable_parent.json");
    if metadata_path.exists() {
        std::fs::remove_file(&metadata_path).map_err(|e| {
            passless_core::Error::Other(format!("Failed to remove metadata file: {}", e))
        })?;
    }

    println!(
        "Portable parent removed (handle 0x{:08X}).",
        metadata.persistent_handle
    );

    Ok(())
}
