use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Convert bytes to lowercase hexadecimal string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Create a file with secure permissions (0o600: owner read/write only)
///
/// This function creates a file with user-only permissions to prevent
/// unauthorized access to sensitive credential data.
pub fn create_secure_file<P: AsRef<Path>>(path: P) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path.as_ref())
}

/// Write data to a file with secure permissions (0o600: owner read/write only)
///
/// This is a convenience function that creates the file with secure permissions
/// and writes the data in one operation.
pub fn write_secure_file<P: AsRef<Path>>(path: P, data: &[u8]) -> io::Result<()> {
    let mut file = create_secure_file(path)?;
    file.write_all(data)
}

/// Create a directory with secure permissions (0o700: owner read/write/execute only)
///
/// This function creates a directory and all its parents with user-only permissions.
/// If the directory already exists, it will set the permissions to 0o700.
pub fn create_secure_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();

    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        return Ok(());
    }

    fs::create_dir_all(path)?;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;

    let mut current = path;
    while let Some(parent) = current.parent() {
        if parent.exists() && parent != current {
            let metadata = fs::metadata(parent)?;
            if metadata.is_dir() {
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        current = parent;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[]), "");
        assert_eq!(bytes_to_hex(&[0x00]), "00");
        assert_eq!(bytes_to_hex(&[0xff]), "ff");
        assert_eq!(bytes_to_hex(&[0x01, 0x23, 0x45, 0x67]), "01234567");
        assert_eq!(bytes_to_hex(&[0xab, 0xcd, 0xef]), "abcdef");
    }

    #[test]
    fn test_create_secure_file() {
        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join("test_file");

        let file = create_secure_file(&file_path).expect("Failed to create secure file");
        drop(file);

        assert!(file_path.exists());

        let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
        let mode = metadata.permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "File should have 0o600 permissions");
    }

    #[test]
    fn test_write_secure_file() {
        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join("test_file");

        write_secure_file(&file_path, b"test data").expect("Failed to write secure file");

        assert!(file_path.exists());

        let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
        let mode = metadata.permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "File should have 0o600 permissions");

        let contents = fs::read(&file_path).expect("Failed to read file");
        assert_eq!(contents, b"test data");
    }

    #[test]
    fn test_create_secure_dir_all() {
        let dir = tempdir().expect("Failed to create temp dir");
        let nested_path = dir.path().join("a/b/c");

        create_secure_dir_all(&nested_path).expect("Failed to create secure directories");

        assert!(nested_path.exists());

        for component in &["a", "a/b", "a/b/c"] {
            let path = dir.path().join(component);
            let metadata = fs::metadata(&path).expect("Failed to get metadata");
            assert!(metadata.is_dir());
            let mode = metadata.permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o700,
                "Directory {} should have 0o700 permissions",
                component
            );
        }
    }

    #[test]
    fn test_create_secure_dir_all_existing() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().join("existing_dir");

        fs::create_dir_all(&path).expect("Failed to create directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("Failed to set permissions");

        create_secure_dir_all(&path).expect("Failed to update permissions");

        let metadata = fs::metadata(&path).expect("Failed to get metadata");
        let mode = metadata.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "Directory should have 0o700 permissions"
        );
    }
}
