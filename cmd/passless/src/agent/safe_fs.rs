//! Pinned directory handles for the daemon's writes into lease and runtime directories.
//!
//! A root daemon writes into directories whose ancestors may belong to a browser user (the
//! browser runtime root must be owned by that user). A path-based `open`, `chown` or
//! `create_dir_all` would follow a symlink that user planted at any component, and let them make
//! root truncate, write or chown an arbitrary file (security review H1). Every daemon write
//! therefore goes through a [`Dir`]:
//!
//! - a directory is reached component by component with `openat(O_DIRECTORY | O_NOFOLLOW)`, so no
//!   symlink is followed anywhere, and is then used through its descriptor, which a later rename or
//!   symlink swap of its path cannot redirect;
//! - a directory the daemon creates is `mkdirat` + `openat(O_NOFOLLOW)` + `fstat`, and must be a
//!   directory owned by the daemon's effective UID (otherwise someone replaced it in between);
//! - a file is created with `openat(O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC)`: an existing entry,
//!   symlink or not, is refused; a rewrite is `unlinkat` and then a fresh exclusive create;
//! - a file the daemon reads from a browser-owned directory is opened with `O_NOFOLLOW`, must be a
//!   regular file owned by the expected user, and is read up to a bound.
//!
//! Directories the daemon writes into stay owned by the daemon; only the browser profile is handed
//! to the browser user, after the daemon's writes into it and before the browser starts.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path};

/// An open directory, reached without following symlinks.
#[derive(Debug)]
pub struct Dir {
    fd: OwnedFd,
}

fn cstr(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{name}' is not a single path component"),
        ));
    }
    CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains a NUL byte"))
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: `stat` is plain data; `fd` is a valid descriptor.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn open_dir_at(dirfd: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: `name` is NUL-terminated; the result is checked.
    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor this function owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn effective_uid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::geteuid() }
}

impl Dir {
    /// Open the absolute `path` from `/`, one component at a time, following no symlink.
    pub fn open_path(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not an absolute path", path.display()),
            ));
        }
        let root = CString::new("/").expect("no NUL");
        // SAFETY: a constant path; the result is checked.
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_RDONLY,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor this function owns.
        let mut dir = Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let name = CString::new(name.as_bytes()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte")
                    })?;
                    dir = Self {
                        fd: open_dir_at(dir.fd.as_raw_fd(), &name).map_err(|e| {
                            io::Error::new(
                                e.kind(),
                                format!("open {} without following symlinks: {e}", path.display()),
                            )
                        })?,
                    };
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{} is not a normalized path", path.display()),
                    ));
                }
            }
        }
        Ok(dir)
    }

    /// Open the existing subdirectory `name`, not following a symlink.
    pub fn open_dir(&self, name: &str) -> io::Result<Self> {
        Ok(Self {
            fd: open_dir_at(self.fd.as_raw_fd(), &cstr(name)?)?,
        })
    }

    /// Create the subdirectory `name` with `mode` and open it. It must not exist; the opened
    /// directory must be the daemon's (a replacement between `mkdirat` and `openat` is refused).
    pub fn create_dir(&self, name: &str, mode: u32) -> io::Result<Self> {
        let c_name = cstr(name)?;
        // SAFETY: `c_name` is NUL-terminated; the result is checked.
        if unsafe { libc::mkdirat(self.fd.as_raw_fd(), c_name.as_ptr(), mode as libc::mode_t) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let dir = Self {
            fd: open_dir_at(self.fd.as_raw_fd(), &c_name)?,
        };
        let st = fstat(dir.fd.as_raw_fd())?;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR || st.st_uid != effective_uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{name} was replaced after it was created"),
            ));
        }
        // `mkdirat` applies the umask; set the mode exactly.
        dir.chmod(mode)?;
        Ok(dir)
    }

    /// Create the file `name` (it must not exist; a symlink in its place is refused) with
    /// `mode`, write `contents` and return it, so the caller can `fchown` it.
    pub fn create_file(&self, name: &str, mode: u32, contents: &[u8]) -> io::Result<File> {
        let c_name = cstr(name)?;
        // SAFETY: `c_name` is NUL-terminated; the result is checked.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor this function owns.
        let mut file = unsafe { File::from_raw_fd(fd) };
        // `openat` applies the umask; set the mode exactly.
        // SAFETY: plain syscall on a descriptor this function owns.
        if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        file.write_all(contents)?;
        Ok(file)
    }

    /// Replace the file `name`: remove whatever entry has that name (never following it), then
    /// create it afresh as [`Dir::create_file`] does.
    pub fn replace_file(&self, name: &str, mode: u32, contents: &[u8]) -> io::Result<File> {
        self.remove_file(name)?;
        self.create_file(name, mode, contents)
    }

    /// Remove the entry `name` if it exists (a symlink is removed itself, never followed).
    pub fn remove_file(&self, name: &str) -> io::Result<()> {
        let c_name = cstr(name)?;
        // SAFETY: `c_name` is NUL-terminated; the result is checked.
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), c_name.as_ptr(), 0) } != 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::NotFound {
                return Err(err);
            }
        }
        Ok(())
    }

    /// Rename `from` to `to` inside this directory.
    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (from, to) = (cstr(from)?, cstr(to)?);
        let fd = self.fd.as_raw_fd();
        // SAFETY: NUL-terminated names; the result is checked.
        if unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Read the regular file `name`, owned by `owner`, up to `limit` bytes. A symlink, another
    /// file type or another owner (for example a hard link to someone else's file) is refused, so
    /// a file planted in a browser-owned directory cannot make the daemon read anything else.
    pub fn read_owned_file(&self, name: &str, owner: u32, limit: u64) -> io::Result<Vec<u8>> {
        let c_name = cstr(name)?;
        // SAFETY: `c_name` is NUL-terminated; the result is checked.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor this function owns.
        let file = unsafe { File::from_raw_fd(fd) };
        let st = fstat(file.as_raw_fd())?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_uid != owner {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{name} is not a regular file owned by uid {owner}"),
            ));
        }
        let mut contents = Vec::new();
        file.take(limit).read_to_end(&mut contents)?;
        Ok(contents)
    }

    /// `fchown` this directory.
    pub fn chown(&self, uid: u32, gid: u32) -> io::Result<()> {
        // SAFETY: plain syscall on a descriptor this handle owns.
        if unsafe { libc::fchown(self.fd.as_raw_fd(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `fchmod` this directory.
    pub fn chmod(&self, mode: u32) -> io::Result<()> {
        // SAFETY: plain syscall on a descriptor this handle owns.
        if unsafe { libc::fchmod(self.fd.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `fsync` this directory.
    pub fn sync(&self) -> io::Result<()> {
        // SAFETY: plain syscall on a descriptor this handle owns.
        if unsafe { libc::fsync(self.fd.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `fstat` this directory.
    pub fn stat(&self) -> io::Result<libc::stat> {
        fstat(self.fd.as_raw_fd())
    }
}

/// `fchown` a file the daemon created.
pub fn chown_file(file: &File, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: plain syscall on a descriptor the caller owns.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;

    /// A file outside the tree an attacker would like the daemon to clobber.
    fn victim(dir: &Path) -> std::path::PathBuf {
        let victim = dir.join("victim");
        fs::write(&victim, b"precious").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        victim
    }

    fn untouched(victim: &Path) {
        assert_eq!(
            fs::read(victim).unwrap(),
            b"precious",
            "the target is untouched"
        );
        let meta = fs::metadata(victim).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o644, "its mode too");
        assert_eq!(meta.uid(), unsafe { libc::geteuid() }, "and its owner");
    }

    #[test]
    fn a_symlink_at_the_leaf_is_refused_and_its_target_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = victim(tmp.path());
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        symlink(&victim, root.join("Preferences")).unwrap();
        let dir = Dir::open_path(&root).unwrap();
        let err = dir.create_file("Preferences", 0o600, b"x").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST), "{err}");
        untouched(&victim);
        let before = fs::metadata(&victim).unwrap();

        // A rewrite removes the symlink itself and creates a fresh file in its place.
        dir.replace_file("Preferences", 0o600, b"fresh").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        assert_eq!(fs::metadata(&victim).unwrap().ino(), before.ino());
        let meta = fs::symlink_metadata(root.join("Preferences")).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        // Reading follows no symlink either.
        symlink(&victim, root.join("DevToolsActivePort")).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(dir.read_owned_file("DevToolsActivePort", uid, 64).is_err());
    }

    #[test]
    fn a_symlink_at_an_intermediate_component_is_refused_and_its_target_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = victim(tmp.path());
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        // `profile` is a symlink to a directory the attacker chose.
        symlink(&elsewhere, root.join("profile")).unwrap();
        let err = Dir::open_path(&root.join("profile")).unwrap_err();
        assert!(
            err.to_string().contains("without following symlinks"),
            "{err}"
        );
        let dir = Dir::open_path(&root).unwrap();
        assert!(dir.open_dir("profile").is_err());
        assert!(dir.create_dir("profile", 0o700).is_err(), "exists");
        assert_eq!(
            fs::read_dir(&elsewhere).unwrap().count(),
            0,
            "nothing written there"
        );
        untouched(&victim);

        // A swap after the directory was opened does not redirect writes through its handle.
        let real = dir.create_dir("lease", 0o700).unwrap();
        fs::rename(root.join("lease"), root.join("moved")).unwrap();
        symlink(&elsewhere, root.join("lease")).unwrap();
        real.create_file("cdp-endpoint", 0o600, b"ws://x").unwrap();
        assert!(root.join("moved").join("cdp-endpoint").is_file());
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    #[test]
    fn created_directories_and_files_get_the_exact_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Dir::open_path(tmp.path()).unwrap();
        let sub = dir.create_dir("sub", 0o710).unwrap();
        assert_eq!(
            fs::metadata(tmp.path().join("sub"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o710
        );
        let file = sub.create_file("f", 0o644, b"data").unwrap();
        drop(file);
        assert_eq!(
            fs::metadata(tmp.path().join("sub/f"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert!(sub.create_file("f", 0o644, b"again").is_err(), "exclusive");
        let uid = unsafe { libc::geteuid() };
        assert_eq!(sub.read_owned_file("f", uid, 2).unwrap(), b"da");
        assert!(
            sub.read_owned_file("f", uid.wrapping_add(1), 64).is_err(),
            "another owner is refused"
        );
        for bad in ["", ".", "..", "a/b"] {
            assert!(sub.create_file(bad, 0o600, b"").is_err(), "{bad:?}");
        }
        assert!(Dir::open_path(Path::new("relative")).is_err());
    }
}
