//! First tranche of #459: build a default-deny filesystem mount plan.
//!
//! A separate plan is intentional: native-path HID containment is not a general
//! filesystem sandbox. The existing launcher must not select a strict plan
//! until the principal identity handshake, browser resources and fail-closed
//! lifecycle are integrated and exercised under distinct UIDs.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MountAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MountSpec {
    /// Preserve the absolute path in the sandbox; no aliases are accepted.
    pub path: PathBuf,
    pub owner: u32,
    pub access: MountAccess,
}

#[derive(Debug)]
pub(super) struct RestrictedMountPlan {
    mounts: Vec<MountSpec>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn normalized(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut rebuilt = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => rebuilt.push(name),
            _ => return false,
        }
    }
    rebuilt.as_os_str() == path.as_os_str()
}

fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

fn validate_layout(mounts: &[MountSpec], forbidden: &[PathBuf]) -> io::Result<()> {
    for path in forbidden {
        if !normalized(path) {
            return Err(invalid(format!("invalid forbidden path: {}", path.display())));
        }
    }
    for (i, mount) in mounts.iter().enumerate() {
        let path = &mount.path;
        if !normalized(path) || path == Path::new("/") {
            return Err(invalid(format!("invalid mount path: {}", path.display())));
        }
        // The wrapper owns these virtual filesystems. Never bind host versions
        // over them or expose a subtree via an otherwise permitted mount.
        if ["/dev", "/proc", "/sys", "/tmp"]
            .iter()
            .any(|reserved| overlap(path, Path::new(reserved)))
        {
            return Err(invalid(format!("reserved mount path: {}", path.display())));
        }
        if forbidden.iter().any(|deny| overlap(path, deny)) {
            return Err(invalid(format!(
                "mount overlaps forbidden storage: {}",
                path.display()
            )));
        }
        if mounts[..i].iter().any(|other| overlap(path, &other.path)) {
            return Err(invalid(format!(
                "duplicate or overlapping mount: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Only accept sources whose names cannot be replaced by an untrusted UID.
/// Parent directories must be trusted and non-writable by group/other; the
/// leaf can belong to the target UID (e.g. its writable workspace). Do not
/// canonicalize untrusted symlinks. This intentionally rejects /tmp-based
/// sources and user-writable ancestors; a future pinned-FD mount path can
/// support additional layouts without relaxing these checks.
///
/// This validates names, ownership and ordinary mode bits, not host mount
/// aliases, hard links or the contents of an operator-authorized directory.
/// The caller must supply the complete protected-path inventory and use
/// trusted, non-overlapping mount trees. Host root is trusted.
fn validate_source(mount: &MountSpec, daemon_uid: u32) -> io::Result<()> {
    let mut path = PathBuf::from("/");
    let parents = mount.path.ancestors().skip(1).collect::<Vec<_>>();
    for parent in parents.into_iter().rev() {
        let meta = fs::symlink_metadata(parent)?;
        if !meta.is_dir()
            || (meta.uid() != 0 && meta.uid() != daemon_uid)
            || meta.mode() & 0o022 != 0
        {
            return Err(invalid(format!(
                "untrusted mount ancestor: {}",
                parent.display()
            )));
        }
    }
    path.push(&mount.path);
    let meta = fs::symlink_metadata(&path)?;
    let kind = meta.file_type();
    if !(kind.is_dir() || kind.is_file() || kind.is_socket())
        || meta.uid() != mount.owner
        || meta.mode() & 0o022 != 0
    {
        return Err(invalid(format!(
            "unexpected mount source type, owner or permissions: {}",
            path.display()
        )));
    }
    Ok(())
}

impl RestrictedMountPlan {
    /// Compile an explicit mount inventory. There is no full-root bind, no
    /// optional bind and no fallback to the native HID-only containment.
    pub(super) fn new(
        mounts: Vec<MountSpec>,
        forbidden: &[PathBuf],
        daemon_uid: u32,
        target_uid: u32,
    ) -> io::Result<Self> {
        if daemon_uid != 0 || target_uid == 0 || target_uid == daemon_uid {
            return Err(invalid("strict mounts require a root daemon and distinct non-root UID"));
        }
        validate_layout(&mounts, forbidden)?;
        for mount in &mounts {
            if mount.access == MountAccess::ReadWrite && mount.owner != target_uid {
                return Err(invalid(format!(
                    "writable mount must belong to the target UID: {}",
                    mount.path.display()
                )));
            }
            if mount.access == MountAccess::ReadOnly
                && mount.owner != daemon_uid
                && mount.owner != target_uid
            {
                return Err(invalid(format!(
                    "read-only mount has an unrelated owner: {}",
                    mount.path.display()
                )));
            }
            validate_source(mount, daemon_uid)?;
        }
        Ok(Self { mounts })
    }

    /// Options for a fresh Bubblewrap root. The launcher still has to supply
    /// a trusted bwrap binary, a controlled environment, a runtime-specific
    /// executable and descriptor policy. No host /proc is mounted here:
    /// process visibility and PID-namespace lifecycle are separate work.
    pub(super) fn bwrap_args(&self) -> Vec<OsString> {
        let mut args = ["--dev", "/dev", "--tmpfs", "/tmp", "--die-with-parent", "--chdir", "/"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        for mount in &self.mounts {
            args.push(OsString::from(match mount.access {
                MountAccess::ReadOnly => "--ro-bind",
                MountAccess::ReadWrite => "--bind",
            }));
            args.push(mount.path.as_os_str().to_owned());
            args.push(mount.path.as_os_str().to_owned());
        }
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(path: &str, access: MountAccess) -> MountSpec {
        MountSpec {
            path: PathBuf::from(path),
            owner: 0,
            access,
        }
    }

    #[test]
    fn rejects_root_relative_and_non_normalized_paths() {
        for path in ["/", "relative", "/usr/../etc", "/usr/./bin", "/usr//bin"] {
            assert!(validate_layout(&[spec(path, MountAccess::ReadOnly)], &[]).is_err(), "{path}");
        }
    }

    #[test]
    fn rejects_host_virtual_filesystems() {
        for path in ["/dev", "/dev/uhid", "/proc/1", "/sys", "/tmp/workspace"] {
            assert!(validate_layout(&[spec(path, MountAccess::ReadOnly)], &[]).is_err(), "{path}");
        }
    }

    #[test]
    fn rejects_both_directions_of_protected_path_overlap() {
        let denied = vec![PathBuf::from("/var/lib/passless")];
        for path in ["/var", "/var/lib/passless", "/var/lib/passless/agent"] {
            assert!(validate_layout(&[spec(path, MountAccess::ReadOnly)], &denied).is_err(), "{path}");
        }
        assert!(validate_layout(&[spec("/var/lib/passless-work", MountAccess::ReadOnly)], &denied).is_ok());
    }

    #[test]
    fn rejects_duplicate_and_nested_mounts() {
        let parent = spec("/opt/agent", MountAccess::ReadOnly);
        let child = spec("/opt/agent/work", MountAccess::ReadWrite);
        assert!(validate_layout(&[parent.clone(), child.clone()], &[]).is_err());
        assert!(validate_layout(&[child, parent.clone()], &[]).is_err());
        assert!(validate_layout(&[parent.clone(), parent], &[]).is_err());
    }

    #[test]
    fn strict_requires_distinct_non_root_identity() {
        assert!(RestrictedMountPlan::new(vec![], &[], 1000, 1001).is_err());
        assert!(RestrictedMountPlan::new(vec![], &[], 0, 0).is_err());
        assert!(RestrictedMountPlan::new(vec![], &[], 0, 1001).is_ok());
    }

    #[test]
    fn refuses_writable_daemon_resource_even_before_mounting() {
        assert!(RestrictedMountPlan::new(
            vec![spec("/var/lib/work", MountAccess::ReadWrite)],
            &[],
            0,
            1001,
        )
        .is_err());
    }

    #[test]
    fn rejects_untrusted_ancestor() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let path = dir.path().join("workspace");
        fs::create_dir(&path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        let mount = MountSpec {
            path,
            owner: meta.uid(),
            access: MountAccess::ReadWrite,
        };
        assert!(validate_source(&mount, meta.uid()).is_err());
    }

    #[test]
    fn bwrap_arguments_have_no_root_bind_or_optional_mount() {
        // Argument compilation is independent of host paths in this unit test.
        let plan = RestrictedMountPlan {
            mounts: vec![
                spec("/usr", MountAccess::ReadOnly),
                spec("/var/lib/agent-work", MountAccess::ReadWrite),
            ],
        };
        let args = plan.bwrap_args();
        let args: Vec<_> = args.iter().map(|arg| arg.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--dev", "/dev", "--tmpfs", "/tmp", "--die-with-parent", "--chdir", "/",
                "--ro-bind", "/usr", "/usr", "--bind", "/var/lib/agent-work", "/var/lib/agent-work",
            ]
        );
        assert!(!args.contains(&"--dev-bind"));
        assert!(!args.iter().any(|arg| arg.ends_with("-try")));
    }
}
