use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn validate_regular_file_fd(fd: i32) -> io::Result<()> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a regular file",
        ));
    }
    let uid = current_uid();
    if stat.st_uid != uid && stat.st_uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file owned by unexpected user",
        ));
    }
    let mode = stat.st_mode & 0o7777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file has insecure permissions",
        ));
    }
    Ok(())
}

pub fn create_secure_file<P: AsRef<Path>>(path: P) -> io::Result<File> {
    let path = path.as_ref();
    let c_path = path_to_cstring(path)?;

    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_TRUNC;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o600u32 as libc::mode_t) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    if let Err(e) = validate_regular_file_fd(fd) {
        unsafe { libc::close(fd) };
        return Err(e);
    }

    Ok(unsafe { File::from_raw_fd(fd) })
}

#[allow(dead_code)]
pub fn write_secure_file<P: AsRef<Path>>(path: P, data: &[u8]) -> io::Result<()> {
    let mut file = create_secure_file(path)?;
    file.write_all(data)
}

pub fn open_dir_fd<P: AsRef<Path>>(path: P) -> io::Result<i32> {
    let path = path.as_ref();
    let c_path = path_to_cstring(path)?;

    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        unsafe { libc::close(fd) };
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a directory",
        ));
    }
    let uid = current_uid();
    if stat.st_uid != uid && stat.st_uid != 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory owned by unexpected user",
        ));
    }
    let mode = stat.st_mode & 0o7777;
    if mode & 0o077 != 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory has insecure permissions",
        ));
    }

    Ok(fd)
}

pub fn atomic_write_in_dir<P: AsRef<Path>>(dir: P, filename: &str, data: &[u8]) -> io::Result<()> {
    let dir = dir.as_ref();
    let dir_fd = open_dir_fd(dir)?;

    let tmp_name = format!(".tmp.{}.{}", std::process::id(), filename);
    let c_tmp = CString::new(tmp_name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid temp filename"))?;
    let c_final = CString::new(filename.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid filename"))?;

    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let tmp_fd = unsafe { libc::openat(dir_fd, c_tmp.as_ptr(), flags, 0o600u32 as libc::mode_t) };
    if tmp_fd < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(dir_fd) };
        return Err(err);
    }

    let result = (|| -> io::Result<()> {
        let mut file = unsafe { File::from_raw_fd(tmp_fd) };
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = result {
        unsafe {
            libc::unlinkat(dir_fd, c_tmp.as_ptr(), 0);
            libc::close(dir_fd);
        }
        return Err(e);
    }

    let rename_ret = unsafe { libc::renameat(dir_fd, c_tmp.as_ptr(), dir_fd, c_final.as_ptr()) };
    if rename_ret != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::unlinkat(dir_fd, c_tmp.as_ptr(), 0);
            libc::close(dir_fd);
        }
        return Err(err);
    }

    unsafe { libc::close(dir_fd) };
    Ok(())
}

fn path_to_cstring(path: &Path) -> io::Result<CString> {
    let bytes = path.as_os_str().as_encoded_bytes();
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null byte"))
}

fn validate_existing_dir(path: &Path) -> io::Result<()> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let c_path = path_to_cstring(path)?;
    if unsafe { libc::lstat(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("symlink detected at {}", path.display()),
        ));
    }
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path component {} is not a directory", path.display()),
        ));
    }
    let uid = current_uid();
    if stat.st_uid != uid && stat.st_uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "path component {} owned by uid {} but current uid is {}",
                path.display(),
                stat.st_uid,
                uid
            ),
        ));
    }
    let mode = stat.st_mode & 0o7777;
    if uid == stat.st_uid && mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "path component {} has insecure permissions {:o}; expected 0o700 or stricter",
                path.display(),
                mode
            ),
        ));
    }
    Ok(())
}

fn create_single_dir(path: &Path) -> io::Result<()> {
    let c_path = path_to_cstring(path)?;
    let ret = unsafe { libc::mkdir(c_path.as_ptr(), 0o700) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::AlreadyExists {
            validate_existing_dir(path)?;
            return Ok(());
        }
        return Err(err);
    }
    validate_existing_dir(path)
}

pub fn create_secure_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    let mut current = PathBuf::new();

    for component in path.components() {
        current.push(component);

        if current == Path::new("/") {
            continue;
        }

        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("symlink detected at {}", current.display()),
                    ));
                }
                if !meta.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("path component {} is not a directory", current.display()),
                    ));
                }
                validate_existing_dir(&current)?;
            }
            Err(_) => {
                create_single_dir(&current)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
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
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let nested_path = dir.path().join("a/b/c");

        create_secure_dir_all(&nested_path).expect("Failed to create secure directories");

        assert!(nested_path.exists());

        let metadata = fs::metadata(&nested_path).expect("Failed to get metadata");
        assert!(metadata.is_dir());
        let mode = metadata.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "Directory a/b/c should have 0o700 permissions"
        );
    }

    #[test]
    fn test_create_secure_dir_all_existing_secure() {
        let dir = tempdir().expect("Failed to create temp dir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("existing_dir");

        fs::create_dir(&path).expect("Failed to create directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("Failed to set permissions");

        create_secure_dir_all(&path).expect("Should succeed for secure existing dir");
    }

    #[test]
    fn test_create_secure_file_rejects_symlink() {
        let dir = tempdir().expect("Failed to create temp dir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let real_file = dir.path().join("real_file");
        let link_file = dir.path().join("link_file");

        fs::write(&real_file, b"original").unwrap();
        symlink(&real_file, &link_file).unwrap();

        let result = create_secure_file(&link_file);
        assert!(result.is_err(), "create_secure_file must reject symlinks");
    }

    #[test]
    fn test_create_secure_dir_all_rejects_symlink_component() {
        let dir = tempdir().expect("Failed to create temp dir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let real_sub = dir.path().join("real_sub");
        let link_sub = dir.path().join("link_sub");
        fs::create_dir(&real_sub).unwrap();
        fs::set_permissions(&real_sub, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real_sub, &link_sub).unwrap();

        let target = link_sub.join("nested");
        let result = create_secure_dir_all(&target);
        assert!(result.is_err(), "must reject symlink in path components");
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    fn test_create_secure_dir_all_rejects_insecure_existing_dir() {
        let dir = tempdir().expect("Failed to create temp dir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let insecure = dir.path().join("insecure");
        fs::create_dir(&insecure).unwrap();
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755)).unwrap();

        let result = create_secure_dir_all(&insecure);
        assert!(
            result.is_err(),
            "must reject existing dir with insecure permissions"
        );
        assert!(result.unwrap_err().to_string().contains("insecure"));
    }

    #[test]
    fn test_create_secure_dir_all_rejects_concurrent_symlink_replacement() {
        let dir = tempdir().expect("Failed to create temp dir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let real_a = dir.path().join("real_a");
        let real_b = dir.path().join("real_b");
        fs::create_dir(&real_a).unwrap();
        fs::set_permissions(&real_a, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&real_b).unwrap();
        fs::set_permissions(&real_b, fs::Permissions::from_mode(0o700)).unwrap();

        let target = dir.path().join("target");
        symlink(&real_b, &target).unwrap();

        let result = create_secure_dir_all(&target);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    fn test_atomic_write_in_dir() {
        let dir = tempdir().expect("Failed to create temp dir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        atomic_write_in_dir(dir.path(), "test.bin", b"credential data")
            .expect("atomic write should succeed");

        let contents = fs::read(dir.path().join("test.bin")).unwrap();
        assert_eq!(contents, b"credential data");

        let meta = fs::metadata(dir.path().join("test.bin")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn test_atomic_write_overwrites_existing() {
        let dir = tempdir().expect("Failed to create temp dir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        atomic_write_in_dir(dir.path(), "test.bin", b"first").unwrap();
        atomic_write_in_dir(dir.path(), "test.bin", b"second").unwrap();

        let contents = fs::read(dir.path().join("test.bin")).unwrap();
        assert_eq!(contents, b"second");
    }

    #[test]
    fn test_open_dir_fd_rejects_symlink() {
        let dir = tempdir().expect("Failed to create temp dir");
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();

        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();

        let result = open_dir_fd(&link);
        assert!(result.is_err());
    }

    #[test]
    fn test_open_dir_fd_rejects_insecure() {
        let dir = tempdir().expect("Failed to create temp dir");
        let insecure = dir.path().join("insecure");
        fs::create_dir(&insecure).unwrap();
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755)).unwrap();

        let result = open_dir_fd(&insecure);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insecure"));
    }
}
