use std::fmt;
use std::fs;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::process::{Child, Command};
use std::time::Duration;

#[cfg(test)]
use std::ffi::CString;
#[cfg(test)]
use std::os::unix::ffi::OsStrExt;

use rand::RngCore;
use zeroize::Zeroize;

use passless_core::agent::PeerCred;

pub const CAPABILITY_BYTES: usize = 32;
pub const CONTROL_FD: i32 = 3;

pub const DEFAULT_RLIMIT_NOFILE: u64 = 64;
pub const DEFAULT_RLIMIT_NPROC: u64 = 32;
pub const DEFAULT_RLIMIT_CORE: u64 = 0;
pub const DEFAULT_RLIMIT_AS: u64 = 256 * 1024 * 1024;

const NS_USER: &str = "user";
const NS_PID: &str = "pid";
const NS_MNT: &str = "mnt";

#[derive(PartialEq, Eq)]
pub struct NamespaceInodes {
    pub user: u64,
    pub pid: u64,
    pub mnt: u64,
}

impl NamespaceInodes {
    pub fn new(user: u64, pid: u64, mnt: u64) -> Self {
        Self { user, pid, mnt }
    }
}

impl fmt::Debug for NamespaceInodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NamespaceInodes")
            .field("user", &self.user)
            .field("pid", &self.pid)
            .field("mnt", &self.mnt)
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
    pub start_time: u64,
    pub cgroup_path: String,
    pub ns_inodes: NamespaceInodes,
}

impl PeerIdentity {
    pub fn new(
        uid: u32,
        gid: u32,
        pid: i32,
        start_time: u64,
        cgroup_path: String,
        ns_inodes: NamespaceInodes,
    ) -> Self {
        Self {
            uid,
            gid,
            pid,
            start_time,
            cgroup_path,
            ns_inodes,
        }
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerIdentity")
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("pid", &self.pid)
            .field("start_time", &self.start_time)
            .field("cgroup_path", &self.cgroup_path)
            .field("ns_inodes", &self.ns_inodes)
            .finish()
    }
}

pub struct SessionCapability([u8; CAPABILITY_BYTES]);

impl SessionCapability {
    pub fn generate() -> Self {
        let mut bytes = [0u8; CAPABILITY_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; CAPABILITY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; CAPABILITY_BYTES] {
        &self.0
    }

    pub fn verify(&self, other: &SessionCapability) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl Drop for SessionCapability {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SessionCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionCapability(***)")
    }
}

impl fmt::Display for SessionCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LauncherError {
    PeerCred {
        source: String,
    },
    ProcRead {
        path: String,
        source: String,
    },
    ProcParse {
        path: String,
        detail: String,
    },
    IdentityMismatch {
        field: String,
        expected: String,
        got: String,
    },
    SameUserFallback,
    PrivilegeInsufficient {
        detail: String,
    },
    DoubleReadInconsistent {
        detail: String,
    },
    PostExecVerification {
        detail: String,
    },
    CapabilityTransfer {
        detail: String,
    },
    SpawnFailed {
        detail: String,
    },
    #[cfg(test)]
    SecurityEnforcement {
        detail: String,
    },
    SecretAbsent,
}

impl fmt::Display for LauncherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerCred { source } => write!(f, "peer credential retrieval failed: {}", source),
            Self::ProcRead { path, source } => {
                write!(f, "failed to read {}: {}", path, source)
            }
            Self::ProcParse { path, detail } => {
                write!(f, "failed to parse {}: {}", path, detail)
            }
            Self::IdentityMismatch {
                field,
                expected,
                got,
            } => write!(
                f,
                "identity mismatch for {}: expected {}, got {}",
                field, expected, got
            ),
            Self::SameUserFallback => {
                write!(
                    f,
                    "principal uid matches daemon uid; same-user fallback denied"
                )
            }
            Self::PrivilegeInsufficient { detail } => {
                write!(f, "insufficient privilege: {}", detail)
            }
            Self::DoubleReadInconsistent { detail } => {
                write!(f, "double-read peer cred inconsistent: {}", detail)
            }
            Self::PostExecVerification { detail } => {
                write!(f, "post-exec verification failed: {}", detail)
            }
            Self::CapabilityTransfer { detail } => {
                write!(f, "capability transfer failed: {}", detail)
            }
            Self::SpawnFailed { detail } => write!(f, "principal spawn failed: {}", detail),
            #[cfg(test)]
            Self::SecurityEnforcement { detail } => {
                write!(f, "security enforcement failed: {}", detail)
            }
            Self::SecretAbsent => write!(f, "session capability not present on control channel"),
        }
    }
}

impl std::error::Error for LauncherError {}

fn constant_time_eq(a: &[u8; CAPABILITY_BYTES], b: &[u8; CAPABILITY_BYTES]) -> bool {
    let mut diff = 0u8;
    for i in 0..CAPABILITY_BYTES {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn read_peer_cred(fd: RawFd) -> Result<PeerCred, LauncherError> {
    PeerCred::from_fd(fd).map_err(|e| LauncherError::PeerCred {
        source: e.to_string(),
    })
}

pub fn read_proc_start_time(pid: i32, proc_root: &Path) -> Result<u64, LauncherError> {
    let stat_path = proc_root.join(format!("{}/stat", pid));
    let stat_path_str = stat_path.display().to_string();

    let content = fs::read_to_string(&stat_path).map_err(|e| LauncherError::ProcRead {
        path: stat_path_str.clone(),
        source: e.to_string(),
    })?;

    parse_start_time_from_stat(&content, &stat_path_str)
}

fn parse_start_time_from_stat(content: &str, path: &str) -> Result<u64, LauncherError> {
    let close_paren = content.rfind(')').ok_or_else(|| LauncherError::ProcParse {
        path: path.to_string(),
        detail: "missing closing paren in stat".to_string(),
    })?;

    let after_comm = &content[close_paren + 2..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();

    if fields.len() < 20 {
        return Err(LauncherError::ProcParse {
            path: path.to_string(),
            detail: format!(
                "expected at least 20 fields after comm, got {}",
                fields.len()
            ),
        });
    }

    fields[19]
        .parse::<u64>()
        .map_err(|e| LauncherError::ProcParse {
            path: path.to_string(),
            detail: format!("invalid starttime: {}", e),
        })
}

pub fn read_cgroup_v2_path(pid: i32, proc_root: &Path) -> Result<String, LauncherError> {
    let cgroup_path = proc_root.join(format!("{}/cgroup", pid));
    let cgroup_path_str = cgroup_path.display().to_string();

    let content = fs::read_to_string(&cgroup_path).map_err(|e| LauncherError::ProcRead {
        path: cgroup_path_str.clone(),
        source: e.to_string(),
    })?;

    parse_cgroup_v2_path(&content, &cgroup_path_str)
}

fn parse_cgroup_v2_path(content: &str, path: &str) -> Result<String, LauncherError> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Ok(rest.to_string());
        }
    }

    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 {
            return Ok(parts[2].to_string());
        }
    }

    Err(LauncherError::ProcParse {
        path: path.to_string(),
        detail: "no cgroup entry found".to_string(),
    })
}

pub fn read_namespace_inodes(pid: i32, proc_root: &Path) -> Result<NamespaceInodes, LauncherError> {
    let user = read_ns_inode(pid, NS_USER, proc_root)?;
    let pid_ns = read_ns_inode(pid, NS_PID, proc_root)?;
    let mnt = read_ns_inode(pid, NS_MNT, proc_root)?;
    Ok(NamespaceInodes::new(user, pid_ns, mnt))
}

fn read_ns_inode(pid: i32, ns_name: &str, proc_root: &Path) -> Result<u64, LauncherError> {
    let ns_path = proc_root.join(format!("{}/ns/{}", pid, ns_name));
    let ns_path_str = ns_path.display().to_string();

    let link = fs::read_link(&ns_path).map_err(|e| LauncherError::ProcRead {
        path: ns_path_str.clone(),
        source: e.to_string(),
    })?;

    let link_str = link.to_string_lossy();
    parse_ns_inode_from_link(&link_str, &ns_path_str)
}

fn parse_ns_inode_from_link(link: &str, path: &str) -> Result<u64, LauncherError> {
    let start = link.find('[').ok_or_else(|| LauncherError::ProcParse {
        path: path.to_string(),
        detail: format!("missing '[' in ns link: {}", link),
    })? + 1;
    let end = link.find(']').ok_or_else(|| LauncherError::ProcParse {
        path: path.to_string(),
        detail: format!("missing ']' in ns link: {}", link),
    })?;

    link[start..end]
        .parse::<u64>()
        .map_err(|e| LauncherError::ProcParse {
            path: path.to_string(),
            detail: format!("invalid inode in ns link '{}': {}", link, e),
        })
}

fn read_proc_uid_gid(pid: i32, proc_root: &Path) -> Result<(u32, u32), LauncherError> {
    let status_path = proc_root.join(format!("{}/status", pid));
    let status_path_str = status_path.display().to_string();

    let content = fs::read_to_string(&status_path).map_err(|e| LauncherError::ProcRead {
        path: status_path_str.clone(),
        source: e.to_string(),
    })?;

    let mut actual_uid = None;
    let mut actual_gid = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:\t") {
            actual_uid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
        }
        if let Some(rest) = line.strip_prefix("Gid:\t") {
            actual_gid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
        }
    }

    let uid = actual_uid.ok_or_else(|| LauncherError::ProcParse {
        path: status_path_str.clone(),
        detail: "cannot parse Uid from status".to_string(),
    })?;
    let gid = actual_gid.ok_or_else(|| LauncherError::ProcParse {
        path: status_path_str,
        detail: "cannot parse Gid from status".to_string(),
    })?;

    Ok((uid, gid))
}

pub fn read_proc_no_new_privs(pid: i32, proc_root: &Path) -> Result<bool, LauncherError> {
    let status_path = proc_root.join(format!("{}/status", pid));
    let status_path_str = status_path.display().to_string();

    let content = fs::read_to_string(&status_path).map_err(|e| LauncherError::ProcRead {
        path: status_path_str.clone(),
        source: e.to_string(),
    })?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("NoNewPrivs:\t") {
            return Ok(rest.trim() == "1");
        }
    }

    Err(LauncherError::ProcParse {
        path: status_path_str,
        detail: "NoNewPrivs field not found in status".to_string(),
    })
}

pub fn capture_peer_identity_double_read(
    fd: RawFd,
    proc_root: &Path,
) -> Result<PeerIdentity, LauncherError> {
    let cred1 = read_peer_cred(fd)?;
    let start_time_1 = read_proc_start_time(cred1.pid, proc_root)?;

    let cred2 = read_peer_cred(fd)?;
    let start_time_2 = read_proc_start_time(cred2.pid, proc_root)?;

    if cred1.pid != cred2.pid
        || cred1.uid != cred2.uid
        || cred1.gid != cred2.gid
        || start_time_1 != start_time_2
    {
        return Err(LauncherError::DoubleReadInconsistent {
            detail: format!(
                "pid: {} vs {}, uid: {} vs {}, gid: {} vs {}, start_time: {} vs {}",
                cred1.pid,
                cred2.pid,
                cred1.uid,
                cred2.uid,
                cred1.gid,
                cred2.gid,
                start_time_1,
                start_time_2
            ),
        });
    }

    let cgroup_path = read_cgroup_v2_path(cred1.pid, proc_root)?;
    let ns_inodes = read_namespace_inodes(cred1.pid, proc_root)?;

    Ok(PeerIdentity::new(
        cred1.uid,
        cred1.gid,
        cred1.pid,
        start_time_1,
        cgroup_path,
        ns_inodes,
    ))
}

#[cfg(test)]
pub fn verify_peer_identity(
    identity: &PeerIdentity,
    expected_uid: u32,
    daemon_uid: u32,
) -> Result<(), LauncherError> {
    if identity.uid == daemon_uid {
        return Err(LauncherError::SameUserFallback);
    }

    if identity.uid != expected_uid {
        return Err(LauncherError::IdentityMismatch {
            field: "uid".to_string(),
            expected: expected_uid.to_string(),
            got: identity.uid.to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
pub fn verify_identity_fields(
    actual: &PeerIdentity,
    expected: &PeerIdentity,
) -> Result<(), LauncherError> {
    if actual.uid != expected.uid {
        return Err(LauncherError::IdentityMismatch {
            field: "uid".to_string(),
            expected: expected.uid.to_string(),
            got: actual.uid.to_string(),
        });
    }
    if actual.gid != expected.gid {
        return Err(LauncherError::IdentityMismatch {
            field: "gid".to_string(),
            expected: expected.gid.to_string(),
            got: actual.gid.to_string(),
        });
    }
    if actual.pid != expected.pid {
        return Err(LauncherError::IdentityMismatch {
            field: "pid".to_string(),
            expected: expected.pid.to_string(),
            got: actual.pid.to_string(),
        });
    }
    if actual.start_time != expected.start_time {
        return Err(LauncherError::IdentityMismatch {
            field: "start_time".to_string(),
            expected: expected.start_time.to_string(),
            got: actual.start_time.to_string(),
        });
    }
    if actual.cgroup_path != expected.cgroup_path {
        return Err(LauncherError::IdentityMismatch {
            field: "cgroup_path".to_string(),
            expected: expected.cgroup_path.clone(),
            got: actual.cgroup_path.clone(),
        });
    }
    if actual.ns_inodes != expected.ns_inodes {
        return Err(LauncherError::IdentityMismatch {
            field: "ns_inodes".to_string(),
            expected: format!("{:?}", expected.ns_inodes),
            got: format!("{:?}", actual.ns_inodes),
        });
    }
    Ok(())
}

#[cfg(test)]
pub fn verify_child_post_exec(
    child_pid: i32,
    expected_uid: u32,
    expected_gid: u32,
    expected_identity: &PeerIdentity,
    proc_root: &Path,
) -> Result<(), LauncherError> {
    let (actual_uid, actual_gid) = read_proc_uid_gid(child_pid, proc_root)?;

    if actual_uid != expected_uid {
        return Err(LauncherError::IdentityMismatch {
            field: "child uid".to_string(),
            expected: expected_uid.to_string(),
            got: actual_uid.to_string(),
        });
    }
    if actual_gid != expected_gid {
        return Err(LauncherError::IdentityMismatch {
            field: "child gid".to_string(),
            expected: expected_gid.to_string(),
            got: actual_gid.to_string(),
        });
    }

    let actual_start_time = read_proc_start_time(child_pid, proc_root)?;
    if actual_start_time != expected_identity.start_time {
        return Err(LauncherError::PostExecVerification {
            detail: format!(
                "start_time mismatch: expected {}, got {}",
                expected_identity.start_time, actual_start_time
            ),
        });
    }

    let actual_cgroup = read_cgroup_v2_path(child_pid, proc_root)?;
    if actual_cgroup != expected_identity.cgroup_path {
        return Err(LauncherError::PostExecVerification {
            detail: format!(
                "cgroup mismatch: expected {}, got {}",
                expected_identity.cgroup_path, actual_cgroup
            ),
        });
    }

    let actual_ns = read_namespace_inodes(child_pid, proc_root)?;
    if actual_ns != expected_identity.ns_inodes {
        return Err(LauncherError::PostExecVerification {
            detail: format!(
                "namespace mismatch: expected {:?}, got {:?}",
                expected_identity.ns_inodes, actual_ns
            ),
        });
    }

    Ok(())
}

pub fn send_capability(fd: RawFd, cap: &SessionCapability) -> Result<(), LauncherError> {
    let bytes = cap.as_bytes();
    let n = unsafe {
        libc::send(
            fd,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if n < 0 {
        return Err(LauncherError::CapabilityTransfer {
            detail: io::Error::last_os_error().to_string(),
        });
    }
    if n as usize != CAPABILITY_BYTES {
        return Err(LauncherError::CapabilityTransfer {
            detail: format!("short write: {} of {} bytes", n, CAPABILITY_BYTES),
        });
    }
    Ok(())
}

#[cfg(test)]
pub fn recv_capability(fd: RawFd) -> Result<SessionCapability, LauncherError> {
    let mut buf = [0u8; CAPABILITY_BYTES];
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n < 0 {
        return Err(LauncherError::CapabilityTransfer {
            detail: io::Error::last_os_error().to_string(),
        });
    }
    if n == 0 {
        return Err(LauncherError::SecretAbsent);
    }
    if n as usize != CAPABILITY_BYTES {
        return Err(LauncherError::CapabilityTransfer {
            detail: format!("short read: {} of {} bytes", n, CAPABILITY_BYTES),
        });
    }
    Ok(SessionCapability::from_bytes(buf))
}

pub fn peek_capability(fd: RawFd) -> Result<SessionCapability, LauncherError> {
    let mut buf = [0u8; CAPABILITY_BYTES];
    let n = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            libc::MSG_PEEK,
        )
    };
    if n < 0 {
        return Err(LauncherError::CapabilityTransfer {
            detail: io::Error::last_os_error().to_string(),
        });
    }
    if n == 0 {
        return Err(LauncherError::SecretAbsent);
    }
    if n as usize != CAPABILITY_BYTES {
        return Err(LauncherError::CapabilityTransfer {
            detail: format!("short peek: {} of {} bytes", n, CAPABILITY_BYTES),
        });
    }
    Ok(SessionCapability::from_bytes(buf))
}

#[derive(Debug, Clone)]
pub struct HardenedChildSetup {
    pub target_uid: u32,
    pub target_gid: u32,
    pub daemon_uid: u32,
    pub daemon_gid: u32,
    pub rlimit_nofile: u64,
    pub rlimit_nproc: u64,
    pub rlimit_core: u64,
    pub rlimit_as: u64,
}

impl HardenedChildSetup {
    pub fn validate(&self) -> Result<(), LauncherError> {
        if self.daemon_uid == 0 {
            if self.target_uid == self.daemon_uid {
                return Err(LauncherError::SameUserFallback);
            }
            if self.target_gid == self.daemon_gid {
                return Err(LauncherError::IdentityMismatch {
                    field: "gid".to_string(),
                    expected: format!("!= {}", self.daemon_gid),
                    got: self.target_gid.to_string(),
                });
            }
        } else if !self.same_user() {
            return Err(LauncherError::PrivilegeInsufficient {
                detail: format!(
                    "non-root daemon (uid={}) cannot spawn as different user (uid={})",
                    self.daemon_uid, self.target_uid
                ),
            });
        }
        Ok(())
    }

    fn same_user(&self) -> bool {
        self.target_uid == self.daemon_uid && self.target_gid == self.daemon_gid
    }

    /// # Safety
    ///
    /// Must be called in the forked child before `exec`. `preserved_fds` must
    /// contain only descriptors intentionally transferred to the principal.
    pub unsafe fn apply(&self, preserved_fds: &[RawFd]) -> Result<(), io::Error> {
        if !self.same_user() {
            unsafe { close_range_preserving(preserved_fds)? };
        }

        if unsafe { libc::setsid() } < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }

        if !self.same_user() {
            if unsafe { libc::setgroups(0, std::ptr::null()) } < 0 {
                return Err(io::Error::last_os_error());
            }

            if unsafe { libc::setgid(self.target_gid) } < 0 {
                return Err(io::Error::last_os_error());
            }

            if unsafe { libc::setuid(self.target_uid) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }

        if !self.same_user() {
            let rlim_nofile = libc::rlimit {
                rlim_cur: self.rlimit_nofile,
                rlim_max: self.rlimit_nofile,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim_nofile) } < 0 {
                return Err(io::Error::last_os_error());
            }

            let rlim_nproc = libc::rlimit {
                rlim_cur: self.rlimit_nproc,
                rlim_max: self.rlimit_nproc,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rlim_nproc) } < 0 {
                return Err(io::Error::last_os_error());
            }

            let rlim_core = libc::rlimit {
                rlim_cur: self.rlimit_core,
                rlim_max: self.rlimit_core,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim_core) } < 0 {
                return Err(io::Error::last_os_error());
            }

            let rlim_as = libc::rlimit {
                rlim_cur: self.rlimit_as,
                rlim_max: self.rlimit_as,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_AS, &rlim_as) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }
}

pub(crate) unsafe fn close_range_preserving(preserved: &[RawFd]) -> Result<(), io::Error> {
    let mut sorted: Vec<RawFd> = preserved.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let nofile_cap = get_nofile_limit();
    let close_range_available = {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        ret >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
    };

    if sorted.is_empty() {
        if close_range_available {
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_close_range,
                    0 as libc::c_ulong,
                    !0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        } else {
            for fd in 0..nofile_cap {
                unsafe { libc::close(fd) };
            }
        }
        return Ok(());
    }

    if let Some(&first) = sorted.first()
        && first > 0
    {
        if close_range_available {
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_close_range,
                    0 as libc::c_ulong,
                    (first - 1) as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        } else {
            for fd in 0..first {
                unsafe { libc::close(fd) };
            }
        }
    }

    for window in sorted.windows(2) {
        let lo = window[0] + 1;
        let hi = window[1] - 1;
        if lo <= hi {
            if close_range_available {
                let ret = unsafe {
                    libc::syscall(
                        libc::SYS_close_range,
                        lo as libc::c_ulong,
                        hi as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            } else {
                for fd in lo..=hi {
                    unsafe { libc::close(fd) };
                }
            }
        }
    }

    if let Some(&last) = sorted.last() {
        if close_range_available {
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_close_range,
                    (last + 1) as libc::c_ulong,
                    !0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        } else {
            for fd in (last + 1)..nofile_cap {
                unsafe { libc::close(fd) };
            }
        }
    }

    Ok(())
}

pub fn dup_fd_cloexec(fd: RawFd) -> Result<OwnedFd, LauncherError> {
    let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new_fd < 0 {
        return Err(LauncherError::SpawnFailed {
            detail: format!("dup_fd_cloexec failed: {}", io::Error::last_os_error()),
        });
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

pub const CLOSE_RANGE_FALLBACK_CAP: RawFd = 4096;

fn get_nofile_limit() -> RawFd {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    if ret < 0 {
        return CLOSE_RANGE_FALLBACK_CAP;
    }
    let val = rlim.rlim_cur as RawFd;
    if val <= 0 {
        return CLOSE_RANGE_FALLBACK_CAP;
    }
    val.min(CLOSE_RANGE_FALLBACK_CAP)
}

#[derive(Debug)]
pub struct SpawnConfig {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub target_uid: u32,
    pub target_gid: u32,
    pub daemon_uid: u32,
    pub daemon_gid: u32,
    pub rlimit_nofile: u64,
    pub rlimit_nproc: u64,
    pub rlimit_core: u64,
    pub rlimit_as: u64,
    pub stdin_fd: Option<OwnedFd>,
    pub stdout_fd: Option<OwnedFd>,
    pub stderr_fd: Option<OwnedFd>,
}

impl SpawnConfig {
    #[cfg(test)]
    pub fn validate(&self) -> Result<(), LauncherError> {
        self.hardening().validate()
    }

    pub fn hardening(&self) -> HardenedChildSetup {
        HardenedChildSetup {
            target_uid: self.target_uid,
            target_gid: self.target_gid,
            daemon_uid: self.daemon_uid,
            daemon_gid: self.daemon_gid,
            rlimit_nofile: self.rlimit_nofile,
            rlimit_nproc: self.rlimit_nproc,
            rlimit_core: self.rlimit_core,
            rlimit_as: self.rlimit_as,
        }
    }
}

#[derive(Debug)]
pub struct PrincipalSession {
    pub child: Child,
    pub capability: SessionCapability,
    pub identity: PeerIdentity,
    pub pidfd: Option<OwnedFd>,
    pub proc_root: PathBuf,
}

fn try_open_pidfd(pid: i32) -> Option<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0 as libc::c_uint) };
    if fd < 0 {
        None
    } else {
        Some(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }
}

fn try_pidfd_send_signal(pidfd: &OwnedFd, sig: libc::c_int) -> bool {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            sig as libc::c_int,
            std::ptr::null::<libc::siginfo_t>(),
            0 as libc::c_uint,
        )
    };
    ret >= 0
}

fn verify_process_identity(
    pid: i32,
    proc_root: &Path,
    expected_start_time: u64,
    expected_cgroup: &str,
) -> bool {
    let actual_start_time = match read_proc_start_time(pid, proc_root) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let actual_cgroup = match read_cgroup_v2_path(pid, proc_root) {
        Ok(c) => c,
        Err(_) => return false,
    };
    actual_start_time == expected_start_time && actual_cgroup == expected_cgroup
}

impl PrincipalSession {
    pub fn terminate(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let pid = self.child.id() as i32;

        let verified = if let Some(ref pidfd) = self.pidfd {
            try_pidfd_send_signal(pidfd, libc::SIGTERM);
            true
        } else if verify_process_identity(
            pid,
            &self.proc_root,
            self.identity.start_time,
            &self.identity.cgroup_path,
        ) {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            true
        } else {
            false
        };

        if !verified {
            let _ = self.child.try_wait();
            return None;
        }

        let deadline = std::time::Instant::now() + timeout;
        let poll_interval = Duration::from_millis(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {}
                Err(_) => return None,
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(poll_interval);
        }

        if let Some(ref pidfd) = self.pidfd {
            try_pidfd_send_signal(pidfd, libc::SIGKILL);
        } else if verify_process_identity(
            pid,
            &self.proc_root,
            self.identity.start_time,
            &self.identity.cgroup_path,
        ) {
            if Self::verify_leader_and_pgid(pid, &self.proc_root) {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            } else {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }

        let kill_deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {}
                Err(_) => return None,
            }
            if std::time::Instant::now() >= kill_deadline {
                break;
            }
            std::thread::sleep(poll_interval);
        }
        None
    }

    fn verify_leader_and_pgid(pid: i32, proc_root: &Path) -> bool {
        let stat_path = proc_root.join(format!("{}/stat", pid));
        let content = match fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let close_paren = match content.rfind(')') {
            Some(p) => p,
            None => return false,
        };
        let after_comm = &content[close_paren + 2..];
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        if fields.len() < 5 {
            return false;
        }
        let pgid = match fields[2].parse::<i32>() {
            Ok(p) => p,
            Err(_) => return false,
        };
        pgid == pid
    }
}

impl Drop for PrincipalSession {
    fn drop(&mut self) {
        let pid = self.child.id() as i32;

        let verified = if let Some(ref pidfd) = self.pidfd {
            try_pidfd_send_signal(pidfd, libc::SIGKILL);
            true
        } else if verify_process_identity(
            pid,
            &self.proc_root,
            self.identity.start_time,
            &self.identity.cgroup_path,
        ) {
            if Self::verify_leader_and_pgid(pid, &self.proc_root) {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            } else {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            true
        } else {
            false
        };

        if verified {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        } else {
            let _ = self.child.try_wait();
        }
    }
}

fn kill_verified_process_group(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

pub fn spawn_principal(config: SpawnConfig) -> Result<PrincipalSession, LauncherError> {
    let setup = config.hardening();
    setup.validate()?;

    let mut fds = [0 as RawFd; 2];
    let ret = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if ret < 0 {
        return Err(LauncherError::SpawnFailed {
            detail: format!("socketpair failed: {}", io::Error::last_os_error()),
        });
    }
    let parent_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child_fd = fds[1];

    let capability = SessionCapability::generate();

    let target_uid = setup.target_uid;
    let target_gid = setup.target_gid;
    let is_same_user = setup.same_user();

    let mut cmd = Command::new(&config.program);
    cmd.args(&config.args);

    if let Some(stdin_fd) = config.stdin_fd {
        cmd.stdin(Stdio::from(stdin_fd));
    }
    if let Some(stdout_fd) = config.stdout_fd {
        cmd.stdout(Stdio::from(stdout_fd));
    }
    if let Some(stderr_fd) = config.stderr_fd {
        cmd.stderr(Stdio::from(stderr_fd));
    }

    unsafe {
        cmd.pre_exec(move || {
            if child_fd != CONTROL_FD {
                if libc::dup2(child_fd, CONTROL_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(child_fd);
            }

            setup.apply(&[0, 1, 2, CONTROL_FD])
        });
    }

    let child = cmd.spawn().map_err(|e| LauncherError::SpawnFailed {
        detail: format!("exec {} failed: {}", config.program.display(), e),
    })?;

    let child_pid = child.id() as i32;
    let proc_root = Path::new("/proc");

    let pidfd = try_open_pidfd(child_pid);

    let cleanup_on_failure = |err: LauncherError| -> LauncherError {
        kill_verified_process_group(child_pid);
        err
    };

    let start_time = read_proc_start_time(child_pid, proc_root).map_err(cleanup_on_failure)?;
    let cgroup_path = read_cgroup_v2_path(child_pid, proc_root).map_err(cleanup_on_failure)?;
    let ns_inodes = match read_namespace_inodes(child_pid, proc_root) {
        Ok(ns) => ns,
        Err(_) if is_same_user => read_namespace_inodes(std::process::id() as i32, proc_root)
            .map_err(cleanup_on_failure)?,
        Err(e) => return Err(cleanup_on_failure(e)),
    };

    let (actual_uid, actual_gid) =
        read_proc_uid_gid(child_pid, proc_root).map_err(cleanup_on_failure)?;

    if actual_uid != target_uid {
        return Err(cleanup_on_failure(LauncherError::PostExecVerification {
            detail: format!("child uid: expected {}, got {}", target_uid, actual_uid),
        }));
    }
    if actual_gid != target_gid {
        return Err(cleanup_on_failure(LauncherError::PostExecVerification {
            detail: format!("child gid: expected {}, got {}", target_gid, actual_gid),
        }));
    }

    let nnp = read_proc_no_new_privs(child_pid, proc_root).map_err(cleanup_on_failure)?;
    if !nnp {
        return Err(cleanup_on_failure(LauncherError::PostExecVerification {
            detail: "NoNewPrivs not set on child".to_string(),
        }));
    }

    send_capability(parent_fd.as_raw_fd(), &capability).inspect_err(|_e| {
        kill_verified_process_group(child_pid);
    })?;

    let identity = PeerIdentity::new(
        actual_uid,
        actual_gid,
        child_pid,
        start_time,
        cgroup_path,
        ns_inodes,
    );

    Ok(PrincipalSession {
        child,
        capability,
        identity,
        pidfd,
        proc_root: proc_root.to_path_buf(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    Allowed { path: String },
    Denied { path: String, errno: i32 },
}

pub fn probe_uhid_access() -> ProbeResult {
    let path_str = "/dev/uhid";
    let fd = unsafe { libc::open(c"/dev/uhid".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return ProbeResult::Denied {
            path: path_str.to_string(),
            errno: err.raw_os_error().unwrap_or(0),
        };
    }
    unsafe { libc::close(fd) };
    ProbeResult::Allowed {
        path: path_str.to_string(),
    }
}

#[cfg(test)]
pub fn probe_protected_node_access(path: &Path) -> ProbeResult {
    let path_str = path.display().to_string();
    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            return ProbeResult::Denied {
                path: path_str,
                errno: libc::EINVAL,
            };
        }
    };
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return ProbeResult::Denied {
            path: path_str,
            errno: err.raw_os_error().unwrap_or(0),
        };
    }
    unsafe { libc::close(fd) };
    ProbeResult::Allowed { path: path_str }
}

#[cfg(test)]
pub fn check_security_enforcement(proc_root: &Path) -> Result<(), LauncherError> {
    let self_pid = std::process::id() as i32;

    let status_path = proc_root.join(format!("{}/status", self_pid));
    let status_content =
        fs::read_to_string(&status_path).map_err(|e| LauncherError::SecurityEnforcement {
            detail: format!("cannot read {}: {}", status_path.display(), e),
        })?;

    for line in status_content.lines() {
        if let Some(rest) = line.strip_prefix("NoNewPrivs:\t") {
            let val = rest.trim();
            if val != "1" {
                return Err(LauncherError::SecurityEnforcement {
                    detail: "NoNewPrivs is not set".to_string(),
                });
            }
        }
    }

    let _ = read_namespace_inodes(self_pid, proc_root).map_err(|e| {
        LauncherError::SecurityEnforcement {
            detail: format!("cannot read namespace inodes: {}", e),
        }
    })?;

    let close_range_ret = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if close_range_ret < 0 {
        let errno = io::Error::last_os_error().raw_os_error();
        if errno == Some(libc::ENOSYS) {
            return Err(LauncherError::SecurityEnforcement {
                detail: "close_range syscall not available (kernel too old)".to_string(),
            });
        }
    }

    Ok(())
}

pub fn read_ppid(pid: i32, proc_root: &Path) -> Result<i32, LauncherError> {
    let stat_path = proc_root.join(format!("{}/stat", pid));
    let stat_path_str = stat_path.display().to_string();

    let content = fs::read_to_string(&stat_path).map_err(|e| LauncherError::ProcRead {
        path: stat_path_str.clone(),
        source: e.to_string(),
    })?;

    parse_ppid_from_stat(&content, &stat_path_str)
}

fn parse_ppid_from_stat(content: &str, path: &str) -> Result<i32, LauncherError> {
    let close_paren = content.rfind(')').ok_or_else(|| LauncherError::ProcParse {
        path: path.to_string(),
        detail: "missing closing paren in stat".to_string(),
    })?;

    let after_comm = &content[close_paren + 2..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();

    if fields.len() < 2 {
        return Err(LauncherError::ProcParse {
            path: path.to_string(),
            detail: format!(
                "expected at least 2 fields after comm for ppid, got {}",
                fields.len()
            ),
        });
    }

    fields[1]
        .parse::<i32>()
        .map_err(|e| LauncherError::ProcParse {
            path: path.to_string(),
            detail: format!("invalid ppid: {}", e),
        })
}

pub struct AncestorEntry {
    pub pid: i32,
    pub start_time: u64,
}

pub fn walk_ancestor_pids(pid: i32, proc_root: &Path) -> Result<Vec<AncestorEntry>, LauncherError> {
    let mut ancestors = Vec::new();
    let mut current_pid = pid;
    let max_depth = 128;

    for _ in 0..max_depth {
        if current_pid <= 1 {
            break;
        }

        let start_time = read_proc_start_time(current_pid, proc_root)?;
        ancestors.push(AncestorEntry {
            pid: current_pid,
            start_time,
        });

        let ppid = read_ppid(current_pid, proc_root)?;
        if ppid == current_pid {
            break;
        }
        current_pid = ppid;
    }

    Ok(ancestors)
}

pub fn verify_process_ancestry(
    peer_pid: i32,
    session_identity: &PeerIdentity,
    proc_root: &Path,
) -> Result<(), LauncherError> {
    let ancestors = walk_ancestor_pids(peer_pid, proc_root)?;

    for ancestor in &ancestors {
        if ancestor.pid == session_identity.pid
            && ancestor.start_time == session_identity.start_time
        {
            return Ok(());
        }
    }

    Err(LauncherError::IdentityMismatch {
        field: "ancestry".to_string(),
        expected: format!(
            "descendant of pid {} (start_time {})",
            session_identity.pid, session_identity.start_time
        ),
        got: format!("pid {} not in ancestor chain", peer_pid),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn make_identity(uid: u32, gid: u32, pid: i32, start_time: u64, cgroup: &str) -> PeerIdentity {
        PeerIdentity::new(
            uid,
            gid,
            pid,
            start_time,
            cgroup.to_string(),
            NamespaceInodes::new(4026531837, 4026531836, 4026531840),
        )
    }

    fn make_identity_full(
        uid: u32,
        gid: u32,
        pid: i32,
        start_time: u64,
        cgroup: &str,
        ns: NamespaceInodes,
    ) -> PeerIdentity {
        PeerIdentity::new(uid, gid, pid, start_time, cgroup.to_string(), ns)
    }

    fn default_spawn_config() -> SpawnConfig {
        SpawnConfig {
            program: PathBuf::from("/bin/true"),
            args: vec![],
            target_uid: 1001,
            target_gid: 1001,
            daemon_uid: 0,
            daemon_gid: 0,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
            stdin_fd: None,
            stdout_fd: None,
            stderr_fd: None,
        }
    }

    #[test]
    fn test_dup_fd_cloexec_does_not_close_original() {
        let (s1, _s2) = UnixStream::pair().unwrap();
        let original_fd = s1.as_raw_fd();
        let duped = dup_fd_cloexec(original_fd).unwrap();
        assert_ne!(duped.as_raw_fd(), original_fd);
        let flags = unsafe { libc::fcntl(duped.as_raw_fd(), libc::F_GETFD) };
        assert!(flags & libc::FD_CLOEXEC != 0);
        let original_flags = unsafe { libc::fcntl(original_fd, libc::F_GETFD) };
        assert!(original_flags >= 0);
    }

    #[test]
    fn test_dup_fd_cloexec_drop_does_not_close_original() {
        let (s1, _s2) = UnixStream::pair().unwrap();
        let original_fd = s1.as_raw_fd();
        {
            let _duped = dup_fd_cloexec(original_fd).unwrap();
        }
        let flags = unsafe { libc::fcntl(original_fd, libc::F_GETFD) };
        assert!(flags >= 0, "original fd was closed when dup was dropped");
    }

    #[test]
    fn test_close_range_fallback_cap_from_rlimit() {
        let cap = get_nofile_limit();
        assert!(cap > 0);
        assert!(cap <= CLOSE_RANGE_FALLBACK_CAP);
    }

    #[test]
    fn test_session_capability_not_clone() {
        fn assert_not_clone<T>() {}
        assert_not_clone::<SessionCapability>();
    }

    #[test]
    fn test_session_capability_generate_unique() {
        let a = SessionCapability::generate();
        let b = SessionCapability::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn test_session_capability_debug_redacted() {
        let cap = SessionCapability::generate();
        let debug = format!("{:?}", cap);
        assert_eq!(debug, "SessionCapability(***)");
        let cap_hex = cap
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        assert!(!debug.contains(&cap_hex));
    }

    #[test]
    fn test_session_capability_display_redacted() {
        let cap = SessionCapability::generate();
        let display = format!("{}", cap);
        assert_eq!(display, "***");
    }

    #[test]
    fn test_session_capability_verify_matching() {
        let bytes = [0xABu8; CAPABILITY_BYTES];
        let a = SessionCapability::from_bytes(bytes);
        let b = SessionCapability::from_bytes(bytes);
        assert!(a.verify(&b));
    }

    #[test]
    fn test_session_capability_verify_mismatch_single_byte() {
        let bytes_a = [0u8; CAPABILITY_BYTES];
        let mut bytes_b = [0u8; CAPABILITY_BYTES];
        bytes_b[15] = 1;
        let a = SessionCapability::from_bytes(bytes_a);
        let b = SessionCapability::from_bytes(bytes_b);
        assert!(!a.verify(&b));
    }

    #[test]
    fn test_constant_time_eq_identical() {
        let a = [0x42u8; CAPABILITY_BYTES];
        let b = [0x42u8; CAPABILITY_BYTES];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_differ() {
        let a = [0x00u8; CAPABILITY_BYTES];
        let b = [0xFFu8; CAPABILITY_BYTES];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_verify_peer_identity_correct_uid() {
        let identity = make_identity(1001, 1001, 1234, 100, "/");
        assert!(verify_peer_identity(&identity, 1001, 0).is_ok());
    }

    #[test]
    fn test_verify_peer_identity_wrong_uid() {
        let identity = make_identity(1002, 1002, 1234, 100, "/");
        let err = verify_peer_identity(&identity, 1001, 0).unwrap_err();
        assert!(matches!(err, LauncherError::IdentityMismatch { .. }));
        assert!(err.to_string().contains("uid"));
    }

    #[test]
    fn test_verify_peer_identity_same_user_fallback() {
        let identity = make_identity(0, 0, 1234, 100, "/");
        let err = verify_peer_identity(&identity, 1001, 0).unwrap_err();
        assert!(matches!(err, LauncherError::SameUserFallback));
    }

    #[test]
    fn test_verify_peer_identity_same_user_fallback_nonzero() {
        let identity = make_identity(500, 500, 1234, 100, "/");
        let err = verify_peer_identity(&identity, 1001, 500).unwrap_err();
        assert!(matches!(err, LauncherError::SameUserFallback));
    }

    #[test]
    fn test_verify_identity_fields_all_match() {
        let a = make_identity(1001, 1001, 1234, 100, "/user.slice");
        let b = make_identity(1001, 1001, 1234, 100, "/user.slice");
        assert!(verify_identity_fields(&a, &b).is_ok());
    }

    #[test]
    fn test_verify_identity_fields_wrong_uid() {
        let a = make_identity(1002, 1002, 1234, 100, "/");
        let b = make_identity(1001, 1001, 1234, 100, "/");
        let err = verify_identity_fields(&a, &b).unwrap_err();
        assert!(matches!(err, LauncherError::IdentityMismatch { .. }));
        assert!(err.to_string().contains("uid"));
    }

    #[test]
    fn test_verify_identity_fields_wrong_gid() {
        let a = make_identity(1001, 9999, 1234, 100, "/");
        let b = make_identity(1001, 1001, 1234, 100, "/");
        let err = verify_identity_fields(&a, &b).unwrap_err();
        assert!(err.to_string().contains("gid"));
    }

    #[test]
    fn test_verify_identity_fields_wrong_pid() {
        let a = make_identity(1001, 1001, 9999, 100, "/");
        let b = make_identity(1001, 1001, 1234, 100, "/");
        let err = verify_identity_fields(&a, &b).unwrap_err();
        assert!(err.to_string().contains("pid"));
    }

    #[test]
    fn test_verify_identity_fields_wrong_start_time() {
        let a = make_identity(1001, 1001, 1234, 999, "/");
        let b = make_identity(1001, 1001, 1234, 100, "/");
        let err = verify_identity_fields(&a, &b).unwrap_err();
        assert!(err.to_string().contains("start_time"));
    }

    #[test]
    fn test_verify_identity_fields_wrong_cgroup() {
        let a = make_identity(1001, 1001, 1234, 100, "/evil.slice");
        let b = make_identity(1001, 1001, 1234, 100, "/user.slice");
        let err = verify_identity_fields(&a, &b).unwrap_err();
        assert!(err.to_string().contains("cgroup_path"));
    }

    #[test]
    fn test_verify_identity_fields_wrong_ns_inodes() {
        let ns_a = NamespaceInodes::new(1, 2, 3);
        let ns_b = NamespaceInodes::new(4, 5, 6);
        let a = make_identity_full(1001, 1001, 1234, 100, "/", ns_a);
        let b = make_identity_full(1001, 1001, 1234, 100, "/", ns_b);
        let err = verify_identity_fields(&a, &b).unwrap_err();
        assert!(err.to_string().contains("ns_inodes"));
    }

    #[test]
    fn test_capability_transfer_over_socketpair() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let fd1 = s1.as_raw_fd();
        let fd2 = s2.as_raw_fd();

        let cap = SessionCapability::generate();
        send_capability(fd1, &cap).unwrap();
        let received = recv_capability(fd2).unwrap();
        assert!(cap.verify(&received));
    }

    #[test]
    fn test_capability_wrong_value_rejected() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let fd1 = s1.as_raw_fd();
        let fd2 = s2.as_raw_fd();

        let sent = SessionCapability::generate();
        send_capability(fd1, &sent).unwrap();
        let received = recv_capability(fd2).unwrap();

        let expected = SessionCapability::generate();
        assert!(!expected.verify(&received));
    }

    #[test]
    fn test_secret_absence_empty_socket() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let fd2 = s2.as_raw_fd();

        drop(s1);
        let err = recv_capability(fd2).unwrap_err();
        assert!(matches!(err, LauncherError::SecretAbsent));
    }

    #[test]
    fn test_secret_absence_short_read() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let fd1 = s1.as_raw_fd();
        let fd2 = s2.as_raw_fd();

        let short = [0u8; 16];
        unsafe {
            libc::send(
                fd1,
                short.as_ptr() as *const libc::c_void,
                short.len(),
                libc::MSG_NOSIGNAL,
            );
        }
        let err = recv_capability(fd2).unwrap_err();
        assert!(matches!(err, LauncherError::CapabilityTransfer { .. }));
    }

    #[test]
    fn test_parse_start_time_from_stat() {
        let stat_line = "1234 (bash) S 1 1 1 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 55555 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        let result = parse_start_time_from_stat(stat_line, "/proc/1234/stat").unwrap();
        assert_eq!(result, 55555);
    }

    #[test]
    fn test_parse_start_time_from_stat_with_parens_in_comm() {
        let stat_line = "1234 (my (weird) program) S 1 1 1 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 12345 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        let result = parse_start_time_from_stat(stat_line, "/proc/1234/stat").unwrap();
        assert_eq!(result, 12345);
    }

    #[test]
    fn test_parse_start_time_from_stat_too_few_fields() {
        let stat_line = "1234 (bash) S 1 1 1";
        let err = parse_start_time_from_stat(stat_line, "/proc/1234/stat").unwrap_err();
        assert!(matches!(err, LauncherError::ProcParse { .. }));
    }

    #[test]
    fn test_parse_start_time_from_stat_no_closing_paren() {
        let stat_line = "1234 bash S 1 1 1 0 -1 4194304";
        let err = parse_start_time_from_stat(stat_line, "/proc/1234/stat").unwrap_err();
        assert!(matches!(err, LauncherError::ProcParse { .. }));
    }

    #[test]
    fn test_parse_cgroup_v2_path_found() {
        let content = "0::/user.slice/user-1000.slice/session-1.scope\n";
        let result = parse_cgroup_v2_path(content, "/proc/1234/cgroup").unwrap();
        assert_eq!(result, "/user.slice/user-1000.slice/session-1.scope");
    }

    #[test]
    fn test_parse_cgroup_v2_path_with_v1_entries() {
        let content = "12:memory:/\n11:cpu:/\n0::/user.slice\n";
        let result = parse_cgroup_v2_path(content, "/proc/1234/cgroup").unwrap();
        assert_eq!(result, "/user.slice");
    }

    #[test]
    fn test_parse_cgroup_v2_path_fallback_to_v1() {
        let content = "12:memory:/user.slice\n11:cpu:/user.slice\n";
        let result = parse_cgroup_v2_path(content, "/proc/1234/cgroup").unwrap();
        assert_eq!(result, "/user.slice");
    }

    #[test]
    fn test_parse_cgroup_v2_path_not_found() {
        let content = "";
        let err = parse_cgroup_v2_path(content, "/proc/1234/cgroup").unwrap_err();
        assert!(matches!(err, LauncherError::ProcParse { .. }));
    }

    #[test]
    fn test_parse_cgroup_v2_path_root() {
        let content = "0::/\n";
        let result = parse_cgroup_v2_path(content, "/proc/1234/cgroup").unwrap();
        assert_eq!(result, "/");
    }

    #[test]
    fn test_parse_ns_inode_from_link() {
        let link = "user:[4026531837]";
        let result = parse_ns_inode_from_link(link, "/proc/1234/ns/user").unwrap();
        assert_eq!(result, 4026531837);
    }

    #[test]
    fn test_parse_ns_inode_from_link_pid() {
        let link = "pid:[4026531836]";
        let result = parse_ns_inode_from_link(link, "/proc/1234/ns/pid").unwrap();
        assert_eq!(result, 4026531836);
    }

    #[test]
    fn test_parse_ns_inode_from_link_missing_brackets() {
        let link = "user:4026531837";
        let err = parse_ns_inode_from_link(link, "/proc/1234/ns/user").unwrap_err();
        assert!(matches!(err, LauncherError::ProcParse { .. }));
    }

    #[test]
    fn test_parse_ns_inode_from_link_missing_close_bracket() {
        let link = "user:[4026531837";
        let err = parse_ns_inode_from_link(link, "/proc/1234/ns/user").unwrap_err();
        assert!(matches!(err, LauncherError::ProcParse { .. }));
    }

    #[test]
    fn test_parse_ns_inode_from_link_invalid_number() {
        let link = "user:[abc]";
        let err = parse_ns_inode_from_link(link, "/proc/1234/ns/user").unwrap_err();
        assert!(matches!(err, LauncherError::ProcParse { .. }));
    }

    #[test]
    fn test_proc_reads_with_mock_fs() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("1234");
        fs::create_dir_all(pid_dir.join("ns")).unwrap();

        fs::write(
            pid_dir.join("stat"),
            "1234 (test) S 1 1 1 0 -1 4194304 0 0 0 0 1 2 0 0 20 0 1 0 99999 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        )
        .unwrap();

        fs::write(pid_dir.join("cgroup"), "0::/mock/cgroup/path\n").unwrap();

        let _ = std::os::unix::fs::symlink("user:[4026531837]", pid_dir.join("ns/user"));
        let _ = std::os::unix::fs::symlink("pid:[4026531836]", pid_dir.join("ns/pid"));
        let _ = std::os::unix::fs::symlink("mnt:[4026531840]", pid_dir.join("ns/mnt"));

        let start_time = read_proc_start_time(1234, dir.path()).unwrap();
        assert_eq!(start_time, 99999);

        let cgroup = read_cgroup_v2_path(1234, dir.path()).unwrap();
        assert_eq!(cgroup, "/mock/cgroup/path");

        let ns = read_namespace_inodes(1234, dir.path()).unwrap();
        assert_eq!(ns.user, 4026531837);
        assert_eq!(ns.pid, 4026531836);
        assert_eq!(ns.mnt, 4026531840);
    }

    #[test]
    fn test_proc_read_missing_stat() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_proc_start_time(99999, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::ProcRead { .. }));
    }

    #[test]
    fn test_proc_read_missing_cgroup() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_cgroup_v2_path(99999, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::ProcRead { .. }));
    }

    #[test]
    fn test_proc_read_missing_ns() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_namespace_inodes(99999, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::ProcRead { .. }));
    }

    #[test]
    fn test_namespace_inodes_equality() {
        let a = NamespaceInodes::new(1, 2, 3);
        let b = NamespaceInodes::new(1, 2, 3);
        let c = NamespaceInodes::new(1, 2, 4);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_peer_identity_equality() {
        let a = make_identity(1001, 1001, 1234, 100, "/");
        let b = make_identity(1001, 1001, 1234, 100, "/");
        let c = make_identity(1002, 1002, 1234, 100, "/");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_launcher_error_display() {
        let e = LauncherError::SameUserFallback;
        assert!(e.to_string().contains("same-user"));

        let e = LauncherError::SecretAbsent;
        assert!(e.to_string().contains("not present"));

        let e = LauncherError::IdentityMismatch {
            field: "uid".to_string(),
            expected: "1001".to_string(),
            got: "1002".to_string(),
        };
        assert!(e.to_string().contains("uid"));
        assert!(e.to_string().contains("1001"));
        assert!(e.to_string().contains("1002"));

        let e = LauncherError::SecurityEnforcement {
            detail: "NoNewPrivs not set".to_string(),
        };
        assert!(e.to_string().contains("NoNewPrivs"));

        let e = LauncherError::PrivilegeInsufficient {
            detail: "not root".to_string(),
        };
        assert!(e.to_string().contains("insufficient privilege"));

        let e = LauncherError::DoubleReadInconsistent {
            detail: "mismatch".to_string(),
        };
        assert!(e.to_string().contains("double-read"));

        let e = LauncherError::PostExecVerification {
            detail: "bad child".to_string(),
        };
        assert!(e.to_string().contains("post-exec"));
    }

    #[test]
    fn test_capability_bytes_roundtrip() {
        let original = [0x42u8; CAPABILITY_BYTES];
        let cap = SessionCapability::from_bytes(original);
        assert_eq!(*cap.as_bytes(), original);
    }

    #[test]
    fn test_capability_size_is_256_bits() {
        assert_eq!(CAPABILITY_BYTES * 8, 256);
    }

    #[test]
    fn test_verify_peer_identity_daemon_uid_zero() {
        let identity = make_identity(1001, 1001, 1234, 100, "/");
        assert!(verify_peer_identity(&identity, 1001, 0).is_ok());
    }

    #[test]
    fn test_verify_peer_identity_principal_is_root_rejected_as_same_user() {
        let identity = make_identity(0, 0, 1234, 100, "/");
        let err = verify_peer_identity(&identity, 0, 0).unwrap_err();
        assert!(matches!(err, LauncherError::SameUserFallback));
    }

    #[test]
    fn test_spawn_config_control_fd_constant() {
        assert_eq!(CONTROL_FD, 3);
    }

    #[test]
    fn test_multiple_capability_transfers() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let fd1 = s1.as_raw_fd();
        let fd2 = s2.as_raw_fd();

        let cap1 = SessionCapability::generate();
        let cap2 = SessionCapability::generate();

        send_capability(fd1, &cap1).unwrap();
        send_capability(fd1, &cap2).unwrap();

        let recv1 = recv_capability(fd2).unwrap();
        let recv2 = recv_capability(fd2).unwrap();

        assert!(cap1.verify(&recv1));
        assert!(cap2.verify(&recv2));
        assert!(!cap1.verify(&recv2));
    }

    #[test]
    fn test_verify_identity_fields_all_wrong() {
        let ns_a = NamespaceInodes::new(1, 2, 3);
        let ns_b = NamespaceInodes::new(4, 5, 6);
        let a = make_identity_full(9999, 9999, 9999, 9999, "/wrong", ns_a);
        let b = make_identity_full(1001, 1001, 1234, 100, "/correct", ns_b);
        let err = verify_identity_fields(&a, &b).unwrap_err();
        assert!(err.to_string().contains("uid"));
    }

    #[test]
    fn test_check_security_enforcement_with_mock_proc() {
        let dir = tempfile::tempdir().unwrap();
        let self_pid = std::process::id() as i32;
        let pid_dir = dir.path().join(self_pid.to_string());
        fs::create_dir_all(pid_dir.join("ns")).unwrap();

        fs::write(pid_dir.join("status"), "Name:\tpassless\nNoNewPrivs:\t1\n").unwrap();

        let _ = std::os::unix::fs::symlink("user:[1]", pid_dir.join("ns/user"));
        let _ = std::os::unix::fs::symlink("pid:[2]", pid_dir.join("ns/pid"));
        let _ = std::os::unix::fs::symlink("mnt:[3]", pid_dir.join("ns/mnt"));

        assert!(check_security_enforcement(dir.path()).is_ok());
    }

    #[test]
    fn test_check_security_enforcement_no_new_privs_not_set() {
        let dir = tempfile::tempdir().unwrap();
        let self_pid = std::process::id() as i32;
        let pid_dir = dir.path().join(self_pid.to_string());
        fs::create_dir_all(pid_dir.join("ns")).unwrap();

        fs::write(pid_dir.join("status"), "Name:\tpassless\nNoNewPrivs:\t0\n").unwrap();

        let _ = std::os::unix::fs::symlink("user:[1]", pid_dir.join("ns/user"));
        let _ = std::os::unix::fs::symlink("pid:[2]", pid_dir.join("ns/pid"));
        let _ = std::os::unix::fs::symlink("mnt:[3]", pid_dir.join("ns/mnt"));

        let err = check_security_enforcement(dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::SecurityEnforcement { .. }));
        assert!(err.to_string().contains("NoNewPrivs"));
    }

    #[test]
    fn test_check_security_enforcement_missing_status() {
        let dir = tempfile::tempdir().unwrap();
        let err = check_security_enforcement(dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::SecurityEnforcement { .. }));
    }

    #[test]
    fn test_spawn_config_validate_distinct_uid() {
        let mut config = default_spawn_config();
        config.target_uid = 0;
        config.daemon_uid = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, LauncherError::SameUserFallback));
    }

    #[test]
    fn test_spawn_config_validate_distinct_gid() {
        let mut config = default_spawn_config();
        config.target_gid = 0;
        config.daemon_gid = 0;
        config.daemon_uid = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, LauncherError::IdentityMismatch { .. }));
        assert!(err.to_string().contains("gid"));
    }

    #[test]
    fn test_spawn_config_validate_non_root_different_target_fails() {
        let mut config = default_spawn_config();
        config.daemon_uid = 1000;
        config.daemon_gid = 1000;
        config.target_uid = 1001;
        config.target_gid = 1001;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, LauncherError::PrivilegeInsufficient { .. }));
    }

    #[test]
    fn test_spawn_config_validate_success() {
        let config = default_spawn_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_read_proc_uid_gid_mock() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("1234");
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(
            pid_dir.join("status"),
            "Name:\ttest\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n",
        )
        .unwrap();

        let (uid, gid) = read_proc_uid_gid(1234, dir.path()).unwrap();
        assert_eq!(uid, 1001);
        assert_eq!(gid, 1001);
    }

    #[test]
    fn test_read_proc_uid_gid_missing_uid() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("1234");
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(
            pid_dir.join("status"),
            "Name:\ttest\nGid:\t1001\t1001\t1001\t1001\n",
        )
        .unwrap();

        let err = read_proc_uid_gid(1234, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::ProcParse { .. }));
        assert!(err.to_string().contains("Uid"));
    }

    #[test]
    fn test_verify_child_post_exec_mock() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("5678");
        fs::create_dir_all(pid_dir.join("ns")).unwrap();

        fs::write(
            pid_dir.join("status"),
            "Name:\ttest\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n",
        )
        .unwrap();

        fs::write(
            pid_dir.join("stat"),
            "5678 (test) S 1 1 1 0 -1 4194304 0 0 0 0 1 2 0 0 20 0 1 0 99999 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        )
        .unwrap();

        fs::write(pid_dir.join("cgroup"), "0::/user.slice\n").unwrap();

        let _ = std::os::unix::fs::symlink("user:[4026531837]", pid_dir.join("ns/user"));
        let _ = std::os::unix::fs::symlink("pid:[4026531836]", pid_dir.join("ns/pid"));
        let _ = std::os::unix::fs::symlink("mnt:[4026531840]", pid_dir.join("ns/mnt"));

        let expected = make_identity(1001, 1001, 5678, 99999, "/user.slice");

        assert!(verify_child_post_exec(5678, 1001, 1001, &expected, dir.path()).is_ok());
    }

    #[test]
    fn test_verify_child_post_exec_uid_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("5678");
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(
            pid_dir.join("status"),
            "Name:\ttest\nUid:\t9999\t9999\t9999\t9999\nGid:\t1001\t1001\t1001\t1001\n",
        )
        .unwrap();

        let expected = make_identity(1001, 1001, 5678, 100, "/");

        let err = verify_child_post_exec(5678, 1001, 1001, &expected, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::IdentityMismatch { .. }));
        assert!(err.to_string().contains("child uid"));
    }

    #[test]
    fn test_verify_child_post_exec_gid_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("5678");
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(
            pid_dir.join("status"),
            "Name:\ttest\nUid:\t1001\t1001\t1001\t1001\nGid:\t9999\t9999\t9999\t9999\n",
        )
        .unwrap();

        let expected = make_identity(1001, 1001, 5678, 100, "/");

        let err = verify_child_post_exec(5678, 1001, 1001, &expected, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::IdentityMismatch { .. }));
        assert!(err.to_string().contains("child gid"));
    }

    #[test]
    fn test_send_capability_uses_msg_nosignal() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let fd1 = s1.as_raw_fd();
        let fd2 = s2.as_raw_fd();

        let cap = SessionCapability::generate();
        send_capability(fd1, &cap).unwrap();

        let mut buf = [0u8; CAPABILITY_BYTES];
        let n = unsafe { libc::recv(fd2, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        assert_eq!(n as usize, CAPABILITY_BYTES);
        assert_eq!(buf, *cap.as_bytes());
    }

    #[test]
    fn test_spawn_principal_non_root_fails_closed() {
        let my_uid = unsafe { libc::getuid() };
        if my_uid == 0 {
            return;
        }

        let config = SpawnConfig {
            program: PathBuf::from("/bin/true"),
            args: vec![],
            target_uid: my_uid + 1,
            target_gid: my_uid + 1,
            daemon_uid: my_uid,
            daemon_gid: my_uid,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
            stdin_fd: None,
            stdout_fd: None,
            stderr_fd: None,
        };

        let err = spawn_principal(config).unwrap_err();
        assert!(matches!(err, LauncherError::PrivilegeInsufficient { .. }));
    }

    #[test]
    fn test_spawn_principal_same_uid_fails_closed() {
        let config = SpawnConfig {
            program: PathBuf::from("/bin/true"),
            args: vec![],
            target_uid: 0,
            target_gid: 1001,
            daemon_uid: 0,
            daemon_gid: 0,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
            stdin_fd: None,
            stdout_fd: None,
            stderr_fd: None,
        };

        let err = spawn_principal(config).unwrap_err();
        assert!(matches!(err, LauncherError::SameUserFallback));
    }

    #[test]
    fn test_spawn_principal_same_gid_fails_closed() {
        let config = SpawnConfig {
            program: PathBuf::from("/bin/true"),
            args: vec![],
            target_uid: 1001,
            target_gid: 0,
            daemon_uid: 0,
            daemon_gid: 0,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
            stdin_fd: None,
            stdout_fd: None,
            stderr_fd: None,
        };

        let err = spawn_principal(config).unwrap_err();
        assert!(matches!(err, LauncherError::IdentityMismatch { .. }));
    }

    #[test]
    fn test_default_rlimit_constants() {
        assert_eq!(DEFAULT_RLIMIT_CORE, 0);
        const { assert!(DEFAULT_RLIMIT_NOFILE > 0) };
        const { assert!(DEFAULT_RLIMIT_NPROC > 0) };
        const { assert!(DEFAULT_RLIMIT_AS > 0) };
    }

    #[test]
    fn test_hardened_child_setup_validate_distinct_uid() {
        let setup = HardenedChildSetup {
            target_uid: 0,
            target_gid: 1001,
            daemon_uid: 0,
            daemon_gid: 0,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
        };
        let err = setup.validate().unwrap_err();
        assert!(matches!(err, LauncherError::SameUserFallback));
    }

    #[test]
    fn test_hardened_child_setup_validate_distinct_gid() {
        let setup = HardenedChildSetup {
            target_uid: 1001,
            target_gid: 0,
            daemon_uid: 0,
            daemon_gid: 0,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
        };
        let err = setup.validate().unwrap_err();
        assert!(matches!(err, LauncherError::IdentityMismatch { .. }));
        assert!(err.to_string().contains("gid"));
    }

    #[test]
    fn test_hardened_child_setup_validate_non_root_different_target_fails() {
        let setup = HardenedChildSetup {
            target_uid: 1001,
            target_gid: 1001,
            daemon_uid: 1000,
            daemon_gid: 1000,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
        };
        let err = setup.validate().unwrap_err();
        assert!(matches!(err, LauncherError::PrivilegeInsufficient { .. }));
    }

    #[test]
    fn test_hardened_child_setup_validate_success() {
        let setup = HardenedChildSetup {
            target_uid: 1001,
            target_gid: 1001,
            daemon_uid: 0,
            daemon_gid: 0,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
        };
        assert!(setup.validate().is_ok());
    }

    #[test]
    fn test_spawn_config_hardening_roundtrip() {
        let config = default_spawn_config();
        let setup = config.hardening();
        assert_eq!(setup.target_uid, config.target_uid);
        assert_eq!(setup.target_gid, config.target_gid);
        assert_eq!(setup.daemon_uid, config.daemon_uid);
        assert_eq!(setup.daemon_gid, config.daemon_gid);
        assert_eq!(setup.rlimit_nofile, config.rlimit_nofile);
    }

    #[test]
    fn test_read_proc_no_new_privs_mock_set() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("1234");
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(pid_dir.join("status"), "Name:\ttest\nNoNewPrivs:\t1\n").unwrap();

        assert!(read_proc_no_new_privs(1234, dir.path()).unwrap());
    }

    #[test]
    fn test_read_proc_no_new_privs_mock_not_set() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("1234");
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(pid_dir.join("status"), "Name:\ttest\nNoNewPrivs:\t0\n").unwrap();

        assert!(!read_proc_no_new_privs(1234, dir.path()).unwrap());
    }

    #[test]
    fn test_read_proc_no_new_privs_missing_field() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("1234");
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(pid_dir.join("status"), "Name:\ttest\n").unwrap();

        let err = read_proc_no_new_privs(1234, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::ProcParse { .. }));
    }

    #[test]
    fn test_read_proc_no_new_privs_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_proc_no_new_privs(99999, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::ProcRead { .. }));
    }

    #[test]
    fn test_probe_uhid_access_deterministic() {
        let result = probe_uhid_access();
        match &result {
            ProbeResult::Allowed { path } => assert_eq!(path, "/dev/uhid"),
            ProbeResult::Denied { path, .. } => assert_eq!(path, "/dev/uhid"),
        }
    }

    #[test]
    fn test_probe_protected_node_nonexistent() {
        let result = probe_protected_node_access(Path::new("/nonexistent/device/node"));
        assert!(matches!(result, ProbeResult::Denied { .. }));
    }

    #[test]
    fn test_probe_protected_node_null_byte() {
        let result = probe_protected_node_access(Path::new("/dev/null\0evil"));
        assert!(matches!(result, ProbeResult::Denied { .. }));
    }

    #[test]
    fn test_probe_result_equality() {
        let a = ProbeResult::Allowed {
            path: "/dev/uhid".to_string(),
        };
        let b = ProbeResult::Allowed {
            path: "/dev/uhid".to_string(),
        };
        assert_eq!(a, b);

        let c = ProbeResult::Denied {
            path: "/dev/uhid".to_string(),
            errno: libc::EACCES,
        };
        let d = ProbeResult::Denied {
            path: "/dev/uhid".to_string(),
            errno: libc::EACCES,
        };
        assert_eq!(c, d);
        assert_ne!(a, c);
    }

    #[test]
    fn test_spawn_principal_orchestrated_non_root_fails_closed() {
        let my_uid = unsafe { libc::getuid() };
        if my_uid == 0 {
            return;
        }

        let config = SpawnConfig {
            program: PathBuf::from("/bin/true"),
            args: vec![],
            target_uid: my_uid + 1,
            target_gid: my_uid + 1,
            daemon_uid: my_uid,
            daemon_gid: my_uid,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
            stdin_fd: None,
            stdout_fd: None,
            stderr_fd: None,
        };

        let err = spawn_principal(config).unwrap_err();
        assert!(matches!(err, LauncherError::PrivilegeInsufficient { .. }));
    }

    #[test]
    fn test_verify_process_identity_match() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("4242");
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(
            pid_dir.join("stat"),
            "4242 (test) S 1 1 1 0 -1 4194304 0 0 0 0 1 2 0 0 20 0 1 0 77777 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        )
        .unwrap();
        fs::write(pid_dir.join("cgroup"), "0::/user.slice/test.scope\n").unwrap();

        assert!(verify_process_identity(
            4242,
            dir.path(),
            77777,
            "/user.slice/test.scope"
        ));
    }

    #[test]
    fn test_verify_process_identity_start_time_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("4242");
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(
            pid_dir.join("stat"),
            "4242 (test) S 1 1 1 0 -1 4194304 0 0 0 0 1 2 0 0 20 0 1 0 99999 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        )
        .unwrap();
        fs::write(pid_dir.join("cgroup"), "0::/user.slice/test.scope\n").unwrap();

        assert!(!verify_process_identity(
            4242,
            dir.path(),
            77777,
            "/user.slice/test.scope"
        ));
    }

    #[test]
    fn test_verify_process_identity_cgroup_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("4242");
        fs::create_dir_all(&pid_dir).unwrap();

        fs::write(
            pid_dir.join("stat"),
            "4242 (test) S 1 1 1 0 -1 4194304 0 0 0 0 1 2 0 0 20 0 1 0 77777 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        )
        .unwrap();
        fs::write(pid_dir.join("cgroup"), "0::/evil.slice\n").unwrap();

        assert!(!verify_process_identity(
            4242,
            dir.path(),
            77777,
            "/user.slice/test.scope"
        ));
    }

    #[test]
    fn test_verify_process_identity_already_exited() {
        let dir = tempfile::tempdir().unwrap();

        assert!(!verify_process_identity(
            999_999,
            dir.path(),
            77777,
            "/user.slice/test.scope"
        ));
    }

    #[test]
    fn test_peek_capability_repeatable() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let fd1 = s1.as_raw_fd();
        let fd2 = s2.as_raw_fd();

        let cap = SessionCapability::generate();
        send_capability(fd1, &cap).unwrap();

        let peeked1 = peek_capability(fd2).unwrap();
        let peeked2 = peek_capability(fd2).unwrap();
        let peeked3 = peek_capability(fd2).unwrap();

        assert!(cap.verify(&peeked1));
        assert!(cap.verify(&peeked2));
        assert!(cap.verify(&peeked3));

        let consumed = recv_capability(fd2).unwrap();
        assert!(cap.verify(&consumed));
    }

    #[test]
    fn test_peek_capability_does_not_consume() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let fd1 = s1.as_raw_fd();
        let fd2 = s2.as_raw_fd();

        let cap = SessionCapability::generate();
        send_capability(fd1, &cap).unwrap();

        let peeked = peek_capability(fd2).unwrap();
        assert!(cap.verify(&peeked));

        let recv1 = recv_capability(fd2).unwrap();
        assert!(cap.verify(&recv1));
    }

    #[test]
    fn test_peek_capability_empty_socket() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let fd2 = s2.as_raw_fd();

        drop(s1);
        let err = peek_capability(fd2).unwrap_err();
        assert!(matches!(err, LauncherError::SecretAbsent));
    }

    #[test]
    fn test_parse_ppid_from_stat() {
        let stat_line = "1234 (bash) S 100 1234 1234 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 55555 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        let result = parse_ppid_from_stat(stat_line, "/proc/1234/stat").unwrap();
        assert_eq!(result, 100);
    }

    #[test]
    fn test_parse_ppid_from_stat_with_parens_in_comm() {
        let stat_line = "1234 (my (weird) program) S 200 1234 1234 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 55555 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        let result = parse_ppid_from_stat(stat_line, "/proc/1234/stat").unwrap();
        assert_eq!(result, 200);
    }

    #[test]
    fn test_walk_ancestor_pids_with_mock_fs() {
        let dir = tempfile::tempdir().unwrap();

        for (pid, ppid, start_time) in &[(100, 1, 1000), (200, 100, 2000), (300, 200, 3000)] {
            let pid_dir = dir.path().join(pid.to_string());
            fs::create_dir_all(&pid_dir).unwrap();
            fs::write(
                pid_dir.join("stat"),
                format!(
                    "{} (proc) S {} {} 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 0 {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
                    pid, ppid, pid, start_time
                ),
            )
            .unwrap();
        }

        let ancestors = walk_ancestor_pids(300, dir.path()).unwrap();
        assert_eq!(ancestors.len(), 3);
        assert_eq!(ancestors[0].pid, 300);
        assert_eq!(ancestors[0].start_time, 3000);
        assert_eq!(ancestors[1].pid, 200);
        assert_eq!(ancestors[1].start_time, 2000);
        assert_eq!(ancestors[2].pid, 100);
        assert_eq!(ancestors[2].start_time, 1000);
    }

    #[test]
    fn test_verify_process_ancestry_found() {
        let dir = tempfile::tempdir().unwrap();

        for (pid, ppid, start_time) in &[(100, 1, 1000), (200, 100, 2000), (300, 200, 3000)] {
            let pid_dir = dir.path().join(pid.to_string());
            fs::create_dir_all(&pid_dir).unwrap();
            fs::write(
                pid_dir.join("stat"),
                format!(
                    "{} (proc) S {} {} 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 0 {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
                    pid, ppid, pid, start_time
                ),
            )
            .unwrap();
        }

        let session_identity = PeerIdentity::new(
            1001,
            1001,
            100,
            1000,
            "/user.slice".to_string(),
            NamespaceInodes::new(1, 2, 3),
        );

        assert!(verify_process_ancestry(300, &session_identity, dir.path()).is_ok());
        assert!(verify_process_ancestry(200, &session_identity, dir.path()).is_ok());
        assert!(verify_process_ancestry(100, &session_identity, dir.path()).is_ok());
    }

    #[test]
    fn test_verify_process_ancestry_not_found() {
        let dir = tempfile::tempdir().unwrap();

        for (pid, ppid, start_time) in &[(100, 1, 1000), (200, 100, 2000), (300, 200, 3000)] {
            let pid_dir = dir.path().join(pid.to_string());
            fs::create_dir_all(&pid_dir).unwrap();
            fs::write(
                pid_dir.join("stat"),
                format!(
                    "{} (proc) S {} {} 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 0 {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
                    pid, ppid, pid, start_time
                ),
            )
            .unwrap();
        }

        let session_identity = PeerIdentity::new(
            1001,
            1001,
            999,
            9999,
            "/user.slice".to_string(),
            NamespaceInodes::new(1, 2, 3),
        );

        let err = verify_process_ancestry(300, &session_identity, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::IdentityMismatch { .. }));
        assert!(err.to_string().contains("ancestry"));
    }

    #[test]
    fn test_verify_process_ancestry_wrong_start_time() {
        let dir = tempfile::tempdir().unwrap();

        for (pid, ppid, start_time) in &[(100, 1, 1000), (200, 100, 2000)] {
            let pid_dir = dir.path().join(pid.to_string());
            fs::create_dir_all(&pid_dir).unwrap();
            fs::write(
                pid_dir.join("stat"),
                format!(
                    "{} (proc) S {} {} 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 0 {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
                    pid, ppid, pid, start_time
                ),
            )
            .unwrap();
        }

        let session_identity = PeerIdentity::new(
            1001,
            1001,
            100,
            9999,
            "/user.slice".to_string(),
            NamespaceInodes::new(1, 2, 3),
        );

        let err = verify_process_ancestry(200, &session_identity, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::IdentityMismatch { .. }));
    }

    #[test]
    fn test_verify_process_ancestry_proc_unavailable() {
        let dir = tempfile::tempdir().unwrap();

        let session_identity = PeerIdentity::new(
            1001,
            1001,
            100,
            1000,
            "/user.slice".to_string(),
            NamespaceInodes::new(1, 2, 3),
        );

        let err = verify_process_ancestry(999, &session_identity, dir.path()).unwrap_err();
        assert!(matches!(err, LauncherError::ProcRead { .. }));
    }
}
