//! TPM portable parent management commands

use passless_core::Result;
use passless_core::config::{TpmAction, tpm_path};

use crate::storage::tpm::portable::PortableParent;

use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use log::info;
use zeroize::Zeroizing;

fn resolve_path(path: Option<String>) -> PathBuf {
    PathBuf::from(path.unwrap_or_else(tpm_path))
}

fn resolve_tcti(tcti: Option<String>) -> Option<String> {
    tcti.or_else(|| Some("device:/dev/tpmrm0".to_string()))
}

fn parse_hex_seed(hex_str: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| passless_core::Error::Other(format!("Invalid hex seed: {}", e)))?;
    if bytes.len() != 32 {
        return Err(passless_core::Error::Other(format!(
            "Seed must be exactly 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        )));
    }
    Ok(Zeroizing::new(bytes))
}

fn warn_if_insecure_permissions(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                eprintln!(
                    "WARNING: {} has group/other permissions set. \
                     Recommended: chmod 600 {}",
                    path.display(),
                    path.display()
                );
                return true;
            }
            false
        }
        Err(_) => false,
    }
}

fn read_hex_seed_from_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    warn_if_insecure_permissions(path);
    let mut file = std::fs::File::open(path).map_err(|e| {
        passless_core::Error::Other(format!(
            "Failed to open seed file {}: {}",
            path.display(),
            e
        ))
    })?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| {
        passless_core::Error::Other(format!(
            "Failed to read seed file {}: {}",
            path.display(),
            e
        ))
    })?;
    let first_line = contents.lines().next().unwrap_or("").trim();
    parse_hex_seed(first_line)
}

fn read_hex_seed_from_stdin() -> Result<Zeroizing<Vec<u8>>> {
    let mut contents = String::new();
    io::stdin().read_to_string(&mut contents).map_err(|e| {
        passless_core::Error::Other(format!("Failed to read seed from stdin: {}", e))
    })?;
    let hex_str = contents.trim();
    parse_hex_seed(hex_str)
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

    let seed: Zeroizing<Vec<u8>> = if generate {
        use rand::RngCore;
        let mut seed_bytes = Zeroizing::new(vec![0u8; 32]);
        rand::thread_rng().fill_bytes(&mut seed_bytes);
        let hex_seed = hex::encode(seed_bytes.as_slice());
        eprintln!("=== RECOVERY SEED (back this up securely!) ===");
        eprintln!("{}", hex_seed);
        eprintln!("=== END RECOVERY SEED ===");
        eprintln!("WARNING: This is the ONLY time the seed will be shown.");
        eprintln!("Store it offline. Anyone with this seed can clone your credentials.");
        seed_bytes
    } else if let Some(ref path) = seed_file {
        read_hex_seed_from_file(path)?
    } else if seed_stdin {
        read_hex_seed_from_stdin()?
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    const VALID_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn test_parse_hex_seed_valid() {
        let seed = parse_hex_seed(VALID_HEX).unwrap();
        assert_eq!(seed.len(), 32);
        assert_eq!(seed[0], 0x00);
        assert_eq!(seed[1], 0x11);
        assert_eq!(seed[31], 0xff);
    }

    #[test]
    fn test_parse_hex_seed_wrong_length() {
        assert!(parse_hex_seed("0011").is_err());
    }

    #[test]
    fn test_parse_hex_seed_invalid_hex() {
        let bad = "zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert!(parse_hex_seed(bad).is_err());
    }

    #[test]
    fn test_read_hex_seed_from_file_valid() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("seed.hex");
        std::fs::write(&seed_path, VALID_HEX).unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let seed = read_hex_seed_from_file(&seed_path).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_read_hex_seed_from_file_first_line_only() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("seed.hex");
        let mut f = std::fs::File::create(&seed_path).unwrap();
        writeln!(f, "{}", VALID_HEX).unwrap();
        writeln!(f, "this line should be ignored").unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let seed = read_hex_seed_from_file(&seed_path).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_read_hex_seed_from_file_trims_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("seed.hex");
        std::fs::write(&seed_path, format!("  {}  \n", VALID_HEX)).unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let seed = read_hex_seed_from_file(&seed_path).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_warn_if_insecure_permissions_detects_group_other() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("seed.hex");
        std::fs::write(&seed_path, VALID_HEX).unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(warn_if_insecure_permissions(&seed_path));
    }

    #[test]
    fn test_warn_if_insecure_permissions_clean() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("seed.hex");
        std::fs::write(&seed_path, VALID_HEX).unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(!warn_if_insecure_permissions(&seed_path));
    }

    #[test]
    fn test_read_hex_seed_from_file_warns_but_succeeds_with_insecure_perms() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("seed.hex");
        std::fs::write(&seed_path, VALID_HEX).unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let seed = read_hex_seed_from_file(&seed_path).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_read_hex_seed_from_stdin_valid() {
        let hex_bytes = format!("{}\n", VALID_HEX);
        let mut cursor = io::Cursor::new(hex_bytes.into_bytes());

        let mut captured = String::new();
        cursor.read_to_string(&mut captured).unwrap();
        let seed = parse_hex_seed(captured.trim()).unwrap();
        assert_eq!(seed.len(), 32);
    }
}
