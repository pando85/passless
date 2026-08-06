//! Seed-resolution helpers for `passless tpm provision`.
//!
//! Pure, non-interactive logic for parsing, reading, and generating recovery
//! seeds. Kept in the lib so it can be unit-tested without the binary crate.

use passless_core::Result;

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use zeroize::Zeroizing;

pub fn parse_hex_seed(hex_str: &str) -> Result<Zeroizing<Vec<u8>>> {
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

pub fn warn_if_insecure_permissions(path: &Path) -> bool {
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

pub fn read_hex_seed_from_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
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

pub fn read_hex_seed_from_stdin() -> Result<Zeroizing<Vec<u8>>> {
    let mut contents = String::new();
    std::io::stdin()
        .read_to_string(&mut contents)
        .map_err(|e| {
            passless_core::Error::Other(format!("Failed to read seed from stdin: {}", e))
        })?;
    let hex_str = contents.trim();
    parse_hex_seed(hex_str)
}

pub fn generate_seed() -> Zeroizing<Vec<u8>> {
    use rand::RngCore;
    let mut seed_bytes = Zeroizing::new(vec![0u8; 32]);
    rand::thread_rng().fill_bytes(&mut seed_bytes);
    seed_bytes
}

pub fn resolve_seed(
    generate: bool,
    seed_file: Option<&Path>,
    seed_stdin: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    if generate {
        Ok(generate_seed())
    } else if let Some(path) = seed_file {
        read_hex_seed_from_file(path)
    } else if seed_stdin {
        read_hex_seed_from_stdin()
    } else {
        Err(passless_core::Error::Other(
            "No seed source specified".to_string(),
        ))
    }
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
        let mut cursor = std::io::Cursor::new(hex_bytes.into_bytes());

        let mut captured = String::new();
        cursor.read_to_string(&mut captured).unwrap();
        let seed = parse_hex_seed(captured.trim()).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_generate_seed_returns_32_bytes() {
        let seed = generate_seed();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_generate_seed_two_calls_differ() {
        let a = generate_seed();
        let b = generate_seed();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn test_resolve_seed_generate() {
        let seed = resolve_seed(true, None, false).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_resolve_seed_file() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("seed.hex");
        std::fs::write(&seed_path, VALID_HEX).unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let seed = resolve_seed(false, Some(&seed_path), false).unwrap();
        assert_eq!(seed.len(), 32);
        assert_eq!(seed[0], 0x00);
        assert_eq!(seed[1], 0x11);
    }

    #[test]
    fn test_resolve_seed_invalid_hex_length() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("seed.hex");
        std::fs::write(&seed_path, "0011").unwrap();
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(resolve_seed(false, Some(&seed_path), false).is_err());
    }
}
