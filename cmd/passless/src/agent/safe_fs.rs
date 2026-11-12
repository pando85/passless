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

/// The deepest directory tree [`Dir::remove_tree`] descends into.
const MAX_REMOVE_DEPTH: usize = 16;

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

    /// Open `path`, an absolute path below `trusted_prefix`, creating what is missing, without
    /// following a symlink anywhere. `trusted_prefix` itself is only opened (it is the system's:
    /// `/tmp`, `/run/user/0`). Every component below it must be a directory owned by the daemon's
    /// effective UID: a missing one is created (mode 0700), a pre-existing one that someone else
    /// owns, or that is a symlink or not a directory, is refused rather than used or chmodded.
    /// The last component is set to exactly `mode`.
    pub fn open_or_create_path(path: &Path, mode: u32, trusted_prefix: &Path) -> io::Result<Self> {
        let relative = path.strip_prefix(trusted_prefix).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is not below {}",
                    path.display(),
                    trusted_prefix.display()
                ),
            )
        })?;
        let owner = effective_uid();
        let mut dir = Self::open_path(trusted_prefix)?;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not a normalized path", path.display()),
                ));
            };
            let name = name.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "path is not valid UTF-8")
            })?;
            let next = match dir.open_dir(name) {
                Ok(existing) => {
                    let st = existing.stat()?;
                    if st.st_uid != owner {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "{} already exists and is owned by uid {}, not by the daemon \
                                 (uid {owner}); refusing to use it",
                                trusted_prefix.join(relative).display(),
                                st.st_uid
                            ),
                        ));
                    }
                    existing
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    dir.create_dir_owned_by(name, 0o700, owner)?
                }
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!(
                            "open {} below {} without following symlinks: {e}",
                            name,
                            trusted_prefix.display()
                        ),
                    ));
                }
            };
            dir = next;
        }
        dir.chmod(mode)?;
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
        self.create_dir_owned_by(name, mode, effective_uid())
    }

    /// [`Dir::create_dir`] with the owner the new directory must have (the daemon's effective UID
    /// outside tests).
    fn create_dir_owned_by(&self, name: &str, mode: u32, owner: u32) -> io::Result<Self> {
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
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR || st.st_uid != owner {
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

    /// Remove the entry `name` below this directory, recursively when it is a directory, without
    /// following a symlink anywhere (a symlink is unlinked itself) and without leaving the
    /// filesystem of this directory. A missing entry is not an error.
    pub fn remove_tree(&self, name: &str) -> io::Result<()> {
        let c_name = cstr(name)?;
        let dev = self.stat()?.st_dev;
        self.remove_entry(&c_name, dev, 0)
    }

    fn remove_entry(&self, name: &CStr, dev: libc::dev_t, depth: usize) -> io::Result<()> {
        // SAFETY: `stat` is plain data; `name` is NUL-terminated; the result is checked.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(err)
            };
        }
        let flags = if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            if depth >= MAX_REMOVE_DEPTH {
                return Err(io::Error::other("directory tree is too deep to remove"));
            }
            if st.st_dev != dev {
                return Err(io::Error::other(
                    "refusing to remove across a filesystem boundary",
                ));
            }
            let child = Self {
                fd: open_dir_at(self.fd.as_raw_fd(), name)?,
            };
            for entry in child.entry_names()? {
                child.remove_entry(&entry, dev, depth + 1)?;
            }
            libc::AT_REMOVEDIR
        } else {
            0
        };
        // SAFETY: `name` is NUL-terminated; the result is checked.
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), flags) } != 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::NotFound {
                return Err(err);
            }
        }
        Ok(())
    }

    /// The names of the entries of this directory (not `.` and `..`).
    fn entry_names(&self) -> io::Result<Vec<CString>> {
        // SAFETY: a plain syscall; the result is checked.
        let dup = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `dup` is a fresh descriptor; `fdopendir` takes it over on success.
        let dirp = unsafe { libc::fdopendir(dup) };
        if dirp.is_null() {
            let err = io::Error::last_os_error();
            // SAFETY: `dup` is still ours when `fdopendir` failed.
            unsafe { libc::close(dup) };
            return Err(err);
        }
        // The duplicate shares the file offset of the original.
        // SAFETY: `dirp` is a valid stream.
        unsafe { libc::rewinddir(dirp) };
        let mut names = Vec::new();
        loop {
            // SAFETY: `dirp` is a valid stream; the entry is read before the next call.
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            // SAFETY: `d_name` is a NUL-terminated name.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                names.push(name.to_owned());
            }
        }
        // SAFETY: `dirp` is valid and closed once (this also closes `dup`).
        unsafe { libc::closedir(dirp) };
        Ok(names)
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
        let file = self.open_regular_file(name, &[owner])?;
        let mut contents = Vec::new();
        file.take(limit).read_to_end(&mut contents)?;
        Ok(contents)
    }

    /// Read the regular file `name`, owned by one of `owners`, and refuse (`InvalidData`) a file
    /// longer than `limit` bytes instead of truncating it: for files whose whole content matters.
    /// The same refusals as [`Dir::read_owned_file`]: no symlink, and only a regular file, so a
    /// device such as `/dev/zero` is never read.
    pub fn read_whole_file(&self, name: &str, owners: &[u32], limit: u64) -> io::Result<Vec<u8>> {
        let file = self.open_regular_file(name, owners)?;
        let mut contents = Vec::new();
        file.take(limit.saturating_add(1))
            .read_to_end(&mut contents)?;
        if contents.len() as u64 > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{name} is longer than {limit} bytes"),
            ));
        }
        Ok(contents)
    }

    /// Open `name` read-only without following a symlink (`ELOOP`) or blocking. The caller checks
    /// the file type, owner and mode with `fstat` on the descriptor.
    pub fn open_nofollow(&self, name: &str) -> io::Result<File> {
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
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Open `name` read-only without following a symlink or blocking, and check that it is a
    /// regular file owned by one of `owners`.
    fn open_regular_file(&self, name: &str, owners: &[u32]) -> io::Result<File> {
        let file = self.open_nofollow(name)?;
        let st = fstat(file.as_raw_fd())?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG || !owners.contains(&st.st_uid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{name} is not a regular file owned by uid {owners:?}"),
            ));
        }
        Ok(file)
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
    fn a_symlink_in_the_middle_of_a_multi_component_path_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir_all(elsewhere.join("sub")).unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        // `root/profile` is a symlink, and the path goes through it to `sub`, a real directory
        // there: a path-based open would succeed, `open_path` refuses at `profile`.
        symlink(&elsewhere, root.join("profile")).unwrap();
        let err = Dir::open_path(&root.join("profile").join("sub")).unwrap_err();
        assert!(
            err.to_string().contains("without following symlinks"),
            "{err}"
        );
        // The same path with a real `profile` opens.
        fs::remove_file(root.join("profile")).unwrap();
        fs::create_dir_all(root.join("profile").join("sub")).unwrap();
        Dir::open_path(&root.join("profile").join("sub")).unwrap();
    }

    #[test]
    fn open_or_create_path_creates_owned_directories_and_refuses_strangers_and_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let trusted = tmp.path();
        let uid = unsafe { libc::geteuid() };

        // Missing components are created, 0700, and the last one gets the exact mode.
        let leaf = trusted.join("base").join("agent").join("sign");
        let dir = Dir::open_or_create_path(&leaf, 0o700, trusted).unwrap();
        assert_eq!(dir.stat().unwrap().st_uid, uid);
        assert_eq!(
            fs::metadata(&leaf).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // Idempotent; the mode is re-applied to a pre-existing directory the daemon owns.
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o755)).unwrap();
        Dir::open_or_create_path(&leaf, 0o700, trusted).unwrap();
        assert_eq!(
            fs::metadata(&leaf).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // A symlink at any owned component is refused, and nothing is written through it.
        let elsewhere = trusted.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&elsewhere, trusted.join("linked")).unwrap();
        assert!(Dir::open_or_create_path(&trusted.join("linked"), 0o700, trusted).is_err());
        let through = trusted.join("linked").join("agent").join("sign");
        assert!(Dir::open_or_create_path(&through, 0o700, trusted).is_err());
        symlink(&elsewhere, trusted.join("base").join("agent").join("link")).unwrap();
        let below = trusted.join("base").join("agent").join("link").join("sign");
        assert!(Dir::open_or_create_path(&below, 0o700, trusted).is_err());
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        assert_eq!(
            fs::metadata(&elsewhere).unwrap().permissions().mode() & 0o777,
            0o755,
            "the symlink target was not chmodded"
        );

        // A file in the way is refused; a path outside the trusted prefix is too.
        fs::write(trusted.join("file"), b"x").unwrap();
        assert!(Dir::open_or_create_path(&trusted.join("file"), 0o700, trusted).is_err());
        assert!(Dir::open_or_create_path(Path::new("/tmp/x"), 0o700, trusted).is_err());
    }

    /// A pre-existing directory owned by another user is refused, not used. Needs a second UID
    /// that owns a directory the test can open: `/` is root's, so this runs for a non-root user.
    #[test]
    fn open_or_create_path_refuses_a_pre_existing_directory_of_another_owner() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        // `/proc` and `/sys` are root-owned directories every user can open.
        let err = Dir::open_or_create_path(Path::new("/proc/sys"), 0o700, Path::new("/proc"))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("not by the daemon"), "{err}");
    }

    #[test]
    fn create_dir_refuses_a_directory_the_daemon_does_not_own() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Dir::open_path(tmp.path()).unwrap();
        let uid = unsafe { libc::geteuid() };
        // As if another user had swapped the directory between `mkdirat` and `openat`.
        let err = dir
            .create_dir_owned_by("swapped", 0o700, uid.wrapping_add(1))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("replaced"), "{err}");
        // The real owner passes, and an existing entry is still refused.
        dir.create_dir_owned_by("mine", 0o700, uid).unwrap();
        assert!(dir.create_dir("mine", 0o700).is_err());
    }

    #[test]
    fn whole_file_reads_refuse_devices_symlinks_oversize_and_strangers() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Dir::open_path(tmp.path()).unwrap();
        let uid = unsafe { libc::geteuid() };
        fs::write(tmp.path().join("ok"), b"12345").unwrap();
        assert_eq!(dir.read_whole_file("ok", &[uid], 5).unwrap(), b"12345");
        let err = dir.read_whole_file("ok", &[uid], 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(
            dir.read_whole_file("ok", &[uid.wrapping_add(1)], 64)
                .is_err()
        );
        assert!(
            dir.read_whole_file("ok", &[uid.wrapping_add(1), uid], 64)
                .is_ok()
        );
        // A planted symlink to an endless device is refused, never read.
        symlink("/dev/zero", tmp.path().join("zero")).unwrap();
        assert!(dir.read_whole_file("zero", &[uid], u64::MAX).is_err());
        // So is a FIFO nobody writes to (it would block a plain read).
        let fifo = std::ffi::CString::new(tmp.path().join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(dir.read_whole_file("fifo", &[uid], 64).is_err());
    }

    #[test]
    fn remove_tree_removes_a_tree_and_never_follows_a_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = victim(tmp.path());
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::write(elsewhere.join("keep"), b"keep").unwrap();
        let tree = tmp.path().join("tree");
        fs::create_dir_all(tree.join("a").join("b")).unwrap();
        fs::write(tree.join("a").join("b").join("f"), b"x").unwrap();
        fs::write(tree.join("top"), b"x").unwrap();
        // A symlink to a directory and to a file: removed as links, targets untouched.
        symlink(&elsewhere, tree.join("a").join("dirlink")).unwrap();
        symlink(&victim, tree.join("filelink")).unwrap();
        fs::create_dir(tree.join("sibling")).unwrap();
        fs::write(tree.join("sibling").join("f"), b"x").unwrap();

        let dir = Dir::open_path(tmp.path()).unwrap();
        dir.remove_tree("tree").unwrap();
        assert!(!tree.exists());
        assert_eq!(fs::read(elsewhere.join("keep")).unwrap(), b"keep");
        untouched(&victim);

        // Missing is fine; a symlink or file at the name is unlinked itself; bad names refused.
        dir.remove_tree("tree").unwrap();
        symlink(&elsewhere, tmp.path().join("link")).unwrap();
        dir.remove_tree("link").unwrap();
        assert!(fs::symlink_metadata(tmp.path().join("link")).is_err());
        assert!(elsewhere.join("keep").exists());
        assert!(dir.remove_tree("../x").is_err());
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
