use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use passless_core::agent::ProfileId;
use passless_core::agent::protocol::{
    AdminRequest, AdminRequestFrame, AdminResponse, AdminResponseFrame, CodecError, ErrorCode,
    PeerCred, PrincipalRequest, PrincipalResponse, PrincipalResponseFrame, ProtocolError,
    ProtocolVersion, RecommendedAction, RequestFrame, ResponseFrame, Role, SeqpacketCodec,
    Validate,
};

use super::launcher::{PeerIdentity, capture_peer_identity_double_read};

const ADMIN_DIR_NAME: &str = "admin";
const ADMIN_SOCKET_NAME: &str = "admin.sock";
const PRINCIPAL_ROOT_NAME: &str = "principal";
const PROFILE_SOCKET_NAME: &str = "sock";
const BASE_DIR_MODE: u32 = 0o700;
const ADMIN_DIR_MODE: u32 = 0o700;
const PRINCIPAL_ROOT_DIR_MODE: u32 = 0o711;
const PROFILE_DIR_MODE: u32 = 0o710;
const ADMIN_SOCK_MODE: u32 = 0o600;
const PROFILE_SOCK_MODE: u32 = 0o660;
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
const LISTEN_BACKLOG: i32 = 8;

#[derive(Debug, Clone)]
pub struct ProfileAccess {
    pub expected_uid: u32,
    pub expected_gid: u32,
}

#[derive(Debug)]
pub enum IpcError {
    Io(io::Error),
    Codec(CodecError),
    PeerRejected {
        reason: String,
    },
    RoleMismatch {
        expected: Role,
        got: Role,
    },
    VersionMismatch(ProtocolError),
    ValidationFailed(ProtocolError),
    Shutdown,
    ConnectionLimit,
    #[cfg(test)]
    MessageLimit,
    UnsafePath {
        detail: String,
    },
    DuplicateAccess {
        profile: String,
        detail: String,
    },
    PrivilegeInsufficient {
        detail: String,
    },
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ipc I/O error: {}", e),
            Self::Codec(e) => write!(f, "codec error: {}", e),
            Self::PeerRejected { reason } => write!(f, "peer rejected: {}", reason),
            Self::RoleMismatch { expected, got } => {
                write!(f, "role mismatch: expected {:?}, got {:?}", expected, got)
            }
            Self::VersionMismatch(e) => write!(f, "version mismatch: {}", e),
            Self::ValidationFailed(e) => write!(f, "validation failed: {}", e),
            Self::Shutdown => write!(f, "server is shut down"),
            Self::ConnectionLimit => write!(f, "concurrent connection limit reached"),
            #[cfg(test)]
            Self::MessageLimit => write!(f, "per-connection message limit reached"),
            Self::UnsafePath { detail } => write!(f, "unsafe path operation: {}", detail),
            Self::DuplicateAccess { profile, detail } => {
                write!(f, "duplicate access for profile {}: {}", profile, detail)
            }
            Self::PrivilegeInsufficient { detail } => {
                write!(f, "insufficient privileges: {}", detail)
            }
        }
    }
}

impl std::error::Error for IpcError {}

impl From<io::Error> for IpcError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CodecError> for IpcError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

struct ProfileDirEntry {
    id: ProfileId,
    sock_path: PathBuf,
    dir_fd: OwnedFd,
}

pub struct RuntimeDir {
    base: PathBuf,
    admin_dir: PathBuf,
    admin_sock_path: PathBuf,
    principal_root: PathBuf,
    principal_root_fd: OwnedFd,
    daemon_uid: u32,
    daemon_gid: u32,
    profile_dirs: BTreeMap<String, ProfileDirEntry>,
}

impl RuntimeDir {
    pub fn create(
        base: &Path,
        daemon_uid: u32,
        daemon_gid: u32,
        profiles: &BTreeMap<String, ProfileAccess>,
    ) -> Result<Self, IpcError> {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            let mut seen_uids: BTreeMap<u32, String> = BTreeMap::new();
            let mut seen_gids: BTreeMap<u32, String> = BTreeMap::new();
            for (id_str, access) in profiles {
                if access.expected_uid == daemon_uid {
                    return Err(IpcError::DuplicateAccess {
                        profile: id_str.clone(),
                        detail: format!("profile uid {} must not equal daemon uid", daemon_uid),
                    });
                }
                if let Some(existing) = seen_uids.get(&access.expected_uid) {
                    return Err(IpcError::DuplicateAccess {
                        profile: id_str.clone(),
                        detail: format!(
                            "uid {} already used by profile {}",
                            access.expected_uid, existing
                        ),
                    });
                }
                if let Some(existing) = seen_gids.get(&access.expected_gid) {
                    return Err(IpcError::DuplicateAccess {
                        profile: id_str.clone(),
                        detail: format!(
                            "gid {} already used by profile {}",
                            access.expected_gid, existing
                        ),
                    });
                }
                seen_uids.insert(access.expected_uid, id_str.clone());
                seen_gids.insert(access.expected_gid, id_str.clone());
            }
        }

        let base = base.to_path_buf();
        std::fs::create_dir_all(&base)?;
        set_dir_mode(&base, BASE_DIR_MODE)?;

        let admin_dir = base.join(ADMIN_DIR_NAME);
        std::fs::create_dir_all(&admin_dir)?;
        set_dir_mode(&admin_dir, ADMIN_DIR_MODE)?;
        safe_chown(&admin_dir, daemon_uid, daemon_gid)?;

        let admin_sock_path = admin_dir.join(ADMIN_SOCKET_NAME);

        let principal_root = base.join(PRINCIPAL_ROOT_NAME);
        std::fs::create_dir_all(&principal_root)?;
        set_dir_mode(&principal_root, PRINCIPAL_ROOT_DIR_MODE)?;
        safe_chown(&principal_root, daemon_uid, daemon_gid)?;

        let principal_root_fd = open_dir_fd(&principal_root)?;

        let mut profile_dirs = BTreeMap::new();
        for (id_str, access) in profiles {
            let profile_id = ProfileId::new(id_str.as_str()).map_err(|e| IpcError::UnsafePath {
                detail: format!("invalid profile id {:?}: {}", id_str, e),
            })?;
            let profile_dir = principal_root.join(id_str.as_str());
            std::fs::create_dir(&profile_dir)?;
            set_dir_mode(&profile_dir, PROFILE_DIR_MODE)?;
            safe_chown(&profile_dir, daemon_uid, access.expected_gid)?;

            let dir_fd = open_dir_fd(&profile_dir)?;
            let sock_path = profile_dir.join(PROFILE_SOCKET_NAME);

            profile_dirs.insert(
                id_str.clone(),
                ProfileDirEntry {
                    id: profile_id,
                    sock_path,
                    dir_fd,
                },
            );
        }

        Ok(Self {
            base,
            admin_dir,
            admin_sock_path,
            principal_root,
            principal_root_fd,
            daemon_uid,
            daemon_gid,
            profile_dirs,
        })
    }

    pub fn admin_socket_path(&self) -> &Path {
        &self.admin_sock_path
    }

    #[cfg(test)]
    pub fn principal_socket_path(&self, profile_id: &ProfileId) -> Option<PathBuf> {
        self.profile_dirs
            .get(profile_id.as_str())
            .map(|e| e.sock_path.clone())
    }

    #[cfg(test)]
    pub fn principal_root_path(&self) -> &Path {
        &self.principal_root
    }

    #[cfg(test)]
    pub fn base_path(&self) -> &Path {
        &self.base
    }

    #[cfg(test)]
    pub fn admin_dir_path(&self) -> &Path {
        &self.admin_dir
    }

    #[cfg(test)]
    pub fn profile_dir_path(&self, profile_id: &ProfileId) -> Option<PathBuf> {
        self.profile_dirs
            .get(profile_id.as_str())
            .map(|_e| self.principal_root.join(profile_id.as_str()))
    }

    pub fn cleanup(&self) {
        safe_unlink_socket(&self.admin_sock_path, self.daemon_uid);

        for entry in self.profile_dirs.values() {
            safe_unlink_socket_at(
                entry.dir_fd.as_raw_fd(),
                PROFILE_SOCKET_NAME,
                self.daemon_uid,
            );
        }

        for entry in self.profile_dirs.values() {
            if let Ok(name) = CString::new(entry.id.as_str()) {
                unsafe {
                    libc::unlinkat(
                        self.principal_root_fd.as_raw_fd(),
                        name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    );
                }
            }
        }

        let _ = std::fs::remove_dir(&self.admin_dir);
        let _ = std::fs::remove_dir(&self.principal_root);
        let _ = std::fs::remove_dir(&self.base);
    }
}

impl Drop for RuntimeDir {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn open_dir_fd(path: &Path) -> Result<OwnedFd, IpcError> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| IpcError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
    let fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(IpcError::Io(io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn safe_chown(path: &Path, uid: u32, gid: u32) -> Result<(), IpcError> {
    let is_root = unsafe { libc::geteuid() == 0 };
    let cur_uid = unsafe { libc::getuid() };
    let cur_gid = unsafe { libc::getgid() };
    if !is_root && (uid != cur_uid || gid != cur_gid) {
        return Err(IpcError::PrivilegeInsufficient {
            detail: format!(
                "cannot chown {:?} to {}:{} (running as {}:{}, need CAP_CHOWN)",
                path, uid, gid, cur_uid, cur_gid
            ),
        });
    }
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| IpcError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if ret < 0 {
        return Err(IpcError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn safe_unlink_socket(path: &Path, expected_uid: u32) {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };

    if meta.file_type().is_symlink() {
        return;
    }

    if !meta.file_type().is_socket() {
        return;
    }

    if meta.uid() != expected_uid {
        return;
    }

    let _ = std::fs::remove_file(path);
}

fn safe_unlink_socket_at(dir_fd: RawFd, name: &str, expected_uid: u32) {
    let name_c = match CString::new(name) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::fstatat(
            dir_fd,
            name_c.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret < 0 {
        return;
    }

    if (stat.st_mode & libc::S_IFMT) != libc::S_IFSOCK {
        return;
    }

    if stat.st_uid != expected_uid {
        return;
    }

    unsafe {
        libc::unlinkat(dir_fd, name_c.as_ptr(), 0);
    }
}

fn set_dir_mode(path: &Path, mode: u32) -> Result<(), IpcError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

fn create_seqpacket_listener(
    path: &Path,
    owner_uid: u32,
    owner_gid: u32,
    sock_mode: u32,
) -> Result<OwnedFd, IpcError> {
    safe_unlink_socket(path, owner_uid);

    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(IpcError::Io(io::Error::last_os_error()));
    }
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let path_bytes = path.as_os_str().as_encoded_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

    if path_bytes.len() >= addr.sun_path.len() {
        return Err(IpcError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long",
        )));
    }

    for (i, &b) in path_bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }

    let bind_ret = unsafe {
        libc::bind(
            owned_fd.as_raw_fd(),
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if bind_ret < 0 {
        return Err(IpcError::Io(io::Error::last_os_error()));
    }

    let listen_ret = unsafe { libc::listen(owned_fd.as_raw_fd(), LISTEN_BACKLOG) };
    if listen_ret < 0 {
        return Err(IpcError::Io(io::Error::last_os_error()));
    }

    set_socket_mode(path, sock_mode)?;
    safe_chown(path, owner_uid, owner_gid)?;

    Ok(owned_fd)
}

fn set_socket_mode(path: &Path, mode: u32) -> Result<(), IpcError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

fn accept_nonblocking(listener: &OwnedFd) -> Result<Option<OwnedFd>, IpcError> {
    let fd = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(IpcError::Io(err));
    }
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn validate_peer_cred(
    fd: RawFd,
    expected_uid: u32,
    expected_gid: Option<u32>,
) -> Result<PeerCred, IpcError> {
    let cred = PeerCred::from_fd(fd).map_err(|e| IpcError::PeerRejected {
        reason: format!("SO_PEERCRED failed: {}", e),
    })?;

    if cred.uid != expected_uid {
        return Err(IpcError::PeerRejected {
            reason: format!("uid mismatch: expected {}, got {}", expected_uid, cred.uid),
        });
    }

    if expected_gid.is_some_and(|gid| cred.gid != gid) {
        return Err(IpcError::PeerRejected {
            reason: format!(
                "gid mismatch: expected {}, got {}",
                expected_gid.unwrap(),
                cred.gid
            ),
        });
    }

    Ok(cred)
}

fn send_response(fd: RawFd, response: &ResponseFrame) -> Result<(), IpcError> {
    SeqpacketCodec::send_msg(fd, response)?;
    Ok(())
}

fn send_error_responses(
    fd: RawFd,
    role: Role,
    seq: u64,
    error: ProtocolError,
) -> Result<(), IpcError> {
    let response = match role {
        Role::Admin => ResponseFrame::Admin(AdminResponseFrame::error(seq, error)),
        Role::Principal => ResponseFrame::Principal(PrincipalResponseFrame::error(seq, error)),
    };
    send_response(fd, &response)
}

pub struct AdminRequestContext {
    pub stdio_fds: Option<StdioFds>,
}

pub struct StdioFds {
    pub stdin: OwnedFd,
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
}

pub trait AdminHandler: Send + Sync {
    fn handle_admin(
        &self,
        request: &AdminRequest,
        cred: &PeerCred,
        ctx: &AdminRequestContext,
    ) -> Result<AdminResponse, ProtocolError>;
}

pub trait PrincipalHandler: Send + Sync {
    fn handle_principal(
        &self,
        profile_id: &str,
        request: &PrincipalRequest,
        cred: &PeerCred,
        identity: &PeerIdentity,
        capability_proof: &passless_core::agent::PrincipalCapabilityProof,
    ) -> Result<PrincipalResponse, ProtocolError>;
}

struct ConnectionCounter {
    current: AtomicUsize,
    max: usize,
}

impl ConnectionCounter {
    fn new(max: usize) -> Self {
        Self {
            current: AtomicUsize::new(0),
            max,
        }
    }

    fn try_acquire(&self) -> Option<ConnectionGuard<'_>> {
        loop {
            let cur = self.current.load(Ordering::Acquire);
            if cur >= self.max {
                return None;
            }
            if self
                .current
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(ConnectionGuard { counter: self });
            }
        }
    }
}

struct ConnectionGuard<'a> {
    counter: &'a ConnectionCounter,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.counter.current.fetch_sub(1, Ordering::Release);
    }
}

pub struct IpcServer {
    _runtime_dir: Option<RuntimeDir>,
    #[cfg(test)]
    admin_sock_path: PathBuf,
    #[cfg(test)]
    principal_root: PathBuf,
    admin_listener: OwnedFd,
    principal_listeners: BTreeMap<String, OwnedFd>,
    daemon_uid: u32,
    profile_access: BTreeMap<String, ProfileAccess>,
    cancel: Arc<AtomicBool>,
    conn_counter: ConnectionCounter,
    proc_root: PathBuf,
}

impl IpcServer {
    #[cfg(test)]
    pub fn new_test_dummy() -> Self {
        let (admin_fd_a, _admin_fd_b) = std::os::unix::net::UnixStream::pair().unwrap();
        let admin_listener = admin_fd_a.into();

        let (_principal_fd_a, _principal_fd_b) = std::os::unix::net::UnixStream::pair().unwrap();

        Self {
            _runtime_dir: None,
            #[cfg(test)]
            admin_sock_path: PathBuf::from("/tmp/passless-test/admin.sock"),
            #[cfg(test)]
            principal_root: PathBuf::from("/tmp/passless-test/principals"),
            admin_listener,
            principal_listeners: BTreeMap::new(),
            daemon_uid: 0,
            profile_access: BTreeMap::new(),
            cancel: Arc::new(AtomicBool::new(false)),
            conn_counter: ConnectionCounter::new(MAX_CONCURRENT_CONNECTIONS),
            proc_root: PathBuf::from("/proc"),
        }
    }

    pub fn bind(
        runtime_dir: RuntimeDir,
        profile_access: BTreeMap<String, ProfileAccess>,
        cancel: Arc<AtomicBool>,
        proc_root: PathBuf,
    ) -> Result<Self, IpcError> {
        let daemon_uid = runtime_dir.daemon_uid;
        let daemon_gid = runtime_dir.daemon_gid;

        let admin_listener = create_seqpacket_listener(
            runtime_dir.admin_socket_path(),
            daemon_uid,
            daemon_gid,
            ADMIN_SOCK_MODE,
        )?;

        let mut principal_listeners = BTreeMap::new();
        for (id_str, access) in &profile_access {
            let entry = runtime_dir
                .profile_dirs
                .get(id_str.as_str())
                .ok_or_else(|| {
                    IpcError::Io(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("no directory for profile: {}", id_str),
                    ))
                })?;
            let fd = create_seqpacket_listener(
                &entry.sock_path,
                daemon_uid,
                access.expected_gid,
                PROFILE_SOCK_MODE,
            )?;
            principal_listeners.insert(id_str.clone(), fd);
        }

        #[cfg(test)]
        let admin_sock_path = runtime_dir.admin_socket_path().to_path_buf();
        #[cfg(test)]
        let principal_root = runtime_dir.principal_root_path().to_path_buf();

        Ok(Self {
            _runtime_dir: Some(runtime_dir),
            #[cfg(test)]
            admin_sock_path,
            #[cfg(test)]
            principal_root,
            admin_listener,
            principal_listeners,
            daemon_uid,
            profile_access,
            cancel,
            conn_counter: ConnectionCounter::new(MAX_CONCURRENT_CONNECTIONS),
            proc_root,
        })
    }

    #[cfg(test)]
    pub fn admin_socket_path(&self) -> &Path {
        &self.admin_sock_path
    }

    #[cfg(test)]
    pub fn principal_socket_path(&self, profile_id: &ProfileId) -> Option<PathBuf> {
        if self.principal_listeners.contains_key(profile_id.as_str()) {
            Some(
                self.principal_root
                    .join(profile_id.as_str())
                    .join(PROFILE_SOCKET_NAME),
            )
        } else {
            None
        }
    }

    pub fn handle_one_admin<A: AdminHandler>(
        &self,
        client_fd: OwnedFd,
        handler: &A,
    ) -> Result<(), IpcError> {
        self.handle_one_admin_inner(client_fd, handler)
    }

    fn handle_one_admin_inner<A: AdminHandler>(
        &self,
        client_fd: OwnedFd,
        handler: &A,
    ) -> Result<(), IpcError> {
        let _guard = self
            .conn_counter
            .try_acquire()
            .ok_or(IpcError::ConnectionLimit)?;

        let raw_fd = client_fd.as_raw_fd();
        let _cred = validate_peer_cred(raw_fd, self.daemon_uid, None)?;

        const EXPECTED_STDIO_FDS: usize = 3;
        let (frame, received_fds): (RequestFrame, Vec<RawFd>) =
            match SeqpacketCodec::recv_msg_with_fds(raw_fd, EXPECTED_STDIO_FDS) {
                Ok(result) => result,
                Err(e) => {
                    let _ = send_error_responses(
                        raw_fd,
                        Role::Admin,
                        0,
                        ProtocolError::new(
                            ErrorCode::MalformedMessage,
                            e.to_string(),
                            RecommendedAction::FixRequest,
                        ),
                    );
                    return Err(IpcError::Codec(e));
                }
            };

        let is_launch = matches!(
            &frame,
            RequestFrame::Admin(AdminRequestFrame {
                action: AdminRequest::LaunchPrincipal { .. },
                ..
            })
        );

        if !is_launch && !received_fds.is_empty() {
            for fd in &received_fds {
                unsafe { libc::close(*fd) };
            }
            let pe = ProtocolError::new(
                ErrorCode::BadRequest,
                "ancillary fds not allowed on this action",
                RecommendedAction::FixRequest,
            );
            let _ = send_error_responses(raw_fd, Role::Admin, frame.seq(), pe.clone());
            return Err(IpcError::ValidationFailed(pe));
        }

        if is_launch && received_fds.len() != EXPECTED_STDIO_FDS {
            for fd in &received_fds {
                unsafe { libc::close(*fd) };
            }
            let pe = ProtocolError::new(
                ErrorCode::BadRequest,
                format!(
                    "LaunchPrincipal requires exactly {} stdio fds, got {}",
                    EXPECTED_STDIO_FDS,
                    received_fds.len()
                ),
                RecommendedAction::FixRequest,
            );
            let _ = send_error_responses(raw_fd, Role::Admin, frame.seq(), pe.clone());
            return Err(IpcError::ValidationFailed(pe));
        }

        if frame.role() != Role::Admin {
            for fd in &received_fds {
                unsafe { libc::close(*fd) };
            }
            let _ = send_error_responses(
                raw_fd,
                Role::Admin,
                frame.seq(),
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    format!("admin socket received {:?} frame", frame.role()),
                    RecommendedAction::Abort,
                ),
            );
            return Err(IpcError::RoleMismatch {
                expected: Role::Admin,
                got: frame.role(),
            });
        }

        if let Err(pe) = ProtocolVersion::negotiate(frame.version()) {
            for fd in &received_fds {
                unsafe { libc::close(*fd) };
            }
            let _ = send_error_responses(raw_fd, Role::Admin, frame.seq(), pe.clone());
            return Err(IpcError::VersionMismatch(pe));
        }

        let admin_frame = match &frame {
            RequestFrame::Admin(f) => f,
            _ => unreachable!(),
        };

        if let Err(ve) = admin_frame.action.validate() {
            for fd in &received_fds {
                unsafe { libc::close(*fd) };
            }
            let pe = ProtocolError::new(
                ErrorCode::BadRequest,
                ve.to_string(),
                RecommendedAction::FixRequest,
            );
            let _ = send_error_responses(raw_fd, Role::Admin, admin_frame.seq, pe.clone());
            return Err(IpcError::ValidationFailed(pe));
        }

        let ctx = if received_fds.len() == EXPECTED_STDIO_FDS {
            let mut fds = received_fds.into_iter();
            let stdin = unsafe { OwnedFd::from_raw_fd(fds.next().unwrap()) };
            let stdout = unsafe { OwnedFd::from_raw_fd(fds.next().unwrap()) };
            let stderr = unsafe { OwnedFd::from_raw_fd(fds.next().unwrap()) };
            AdminRequestContext {
                stdio_fds: Some(StdioFds {
                    stdin,
                    stdout,
                    stderr,
                }),
            }
        } else {
            AdminRequestContext { stdio_fds: None }
        };

        match handler.handle_admin(&admin_frame.action, &_cred, &ctx) {
            Ok(response_action) => {
                let response =
                    ResponseFrame::Admin(AdminResponseFrame::ok(admin_frame.seq, response_action));
                send_response(raw_fd, &response)?;
            }
            Err(pe) => {
                let _ = send_error_responses(raw_fd, Role::Admin, admin_frame.seq, pe);
            }
        }

        Ok(())
    }

    pub fn handle_one_principal<P: PrincipalHandler>(
        &self,
        client_fd: OwnedFd,
        profile_id: &ProfileId,
        handler: &P,
    ) -> Result<(), IpcError> {
        self.handle_one_principal_inner(client_fd, profile_id, handler)
    }

    fn handle_one_principal_inner<P: PrincipalHandler>(
        &self,
        client_fd: OwnedFd,
        profile_id: &ProfileId,
        handler: &P,
    ) -> Result<(), IpcError> {
        let _guard = self
            .conn_counter
            .try_acquire()
            .ok_or(IpcError::ConnectionLimit)?;

        let access = self
            .profile_access
            .get(profile_id.as_str())
            .ok_or_else(|| {
                IpcError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no access entry for profile: {}", profile_id),
                ))
            })?;

        let raw_fd = client_fd.as_raw_fd();

        let identity = capture_peer_identity_double_read(raw_fd, &self.proc_root).map_err(|e| {
            IpcError::PeerRejected {
                reason: format!("peer identity capture failed: {}", e),
            }
        })?;

        if identity.uid != access.expected_uid {
            return Err(IpcError::PeerRejected {
                reason: format!(
                    "uid mismatch: expected {}, got {}",
                    access.expected_uid, identity.uid
                ),
            });
        }

        if identity.gid != access.expected_gid {
            return Err(IpcError::PeerRejected {
                reason: format!(
                    "gid mismatch: expected {}, got {}",
                    access.expected_gid, identity.gid
                ),
            });
        }

        let cred = PeerCred {
            pid: identity.pid,
            uid: identity.uid,
            gid: identity.gid,
        };

        let frame: RequestFrame = match SeqpacketCodec::recv_msg(raw_fd) {
            Ok(f) => f,
            Err(e) => {
                let _ = send_error_responses(
                    raw_fd,
                    Role::Principal,
                    0,
                    ProtocolError::new(
                        ErrorCode::MalformedMessage,
                        e.to_string(),
                        RecommendedAction::FixRequest,
                    ),
                );
                return Err(IpcError::Codec(e));
            }
        };

        if frame.role() != Role::Principal {
            let _ = send_error_responses(
                raw_fd,
                Role::Principal,
                frame.seq(),
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    format!("principal socket received {:?} frame", frame.role()),
                    RecommendedAction::Abort,
                ),
            );
            return Err(IpcError::RoleMismatch {
                expected: Role::Principal,
                got: frame.role(),
            });
        }

        if let Err(pe) = ProtocolVersion::negotiate(frame.version()) {
            let _ = send_error_responses(raw_fd, Role::Principal, frame.seq(), pe.clone());
            return Err(IpcError::VersionMismatch(pe));
        }

        let principal_frame = match &frame {
            RequestFrame::Principal(f) => f,
            _ => unreachable!(),
        };

        if let Err(ve) = principal_frame.action.validate() {
            let pe = ProtocolError::new(
                ErrorCode::BadRequest,
                ve.to_string(),
                RecommendedAction::FixRequest,
            );
            let _ = send_error_responses(raw_fd, Role::Principal, principal_frame.seq, pe.clone());
            return Err(IpcError::ValidationFailed(pe));
        }

        match handler.handle_principal(
            profile_id.as_str(),
            &principal_frame.action,
            &cred,
            &identity,
            &principal_frame.capability_proof,
        ) {
            Ok(response_action) => {
                let response = ResponseFrame::Principal(PrincipalResponseFrame::ok(
                    principal_frame.seq,
                    response_action,
                ));
                send_response(raw_fd, &response)?;
            }
            Err(pe) => {
                let _ = send_error_responses(raw_fd, Role::Principal, principal_frame.seq, pe);
            }
        }

        Ok(())
    }

    pub fn accept_admin_connection(&self) -> Result<Option<OwnedFd>, IpcError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(IpcError::Shutdown);
        }
        accept_nonblocking(&self.admin_listener)
    }

    pub fn accept_principal_connection(
        &self,
        profile_id: &ProfileId,
    ) -> Result<Option<OwnedFd>, IpcError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(IpcError::Shutdown);
        }
        let listener = self
            .principal_listeners
            .get(profile_id.as_str())
            .ok_or_else(|| {
                IpcError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no listener for profile: {}", profile_id),
                ))
            })?;
        accept_nonblocking(listener)
    }

    #[cfg(test)]
    pub fn is_shutdown(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passless_core::agent::protocol::{
        AdminRequestFrame, AdminResponseFrame, CAPABILITY_PROOF_BYTES, CURRENT_VERSION,
        MAX_MESSAGE_SIZE, PrincipalCapabilityProof, PrincipalRequestFrame, PrincipalResponseFrame,
    };
    use std::os::unix::io::RawFd;

    struct TestAdminHandler;

    impl AdminHandler for TestAdminHandler {
        fn handle_admin(
            &self,
            request: &AdminRequest,
            _cred: &PeerCred,
            _ctx: &super::AdminRequestContext,
        ) -> Result<AdminResponse, ProtocolError> {
            match request {
                AdminRequest::Ping => Ok(AdminResponse::Pong),
                AdminRequest::Status => {
                    Ok(AdminResponse::Status(passless_core::agent::DaemonStatus {
                        daemon_version: "test".into(),
                        protocol_version: CURRENT_VERSION,
                        backend: "test".into(),
                        uptime_secs: 0,
                        credential_count: 0,
                    }))
                }
                _ => Ok(AdminResponse::Pong),
            }
        }
    }

    struct TestPrincipalHandler;

    impl PrincipalHandler for TestPrincipalHandler {
        fn handle_principal(
            &self,
            _profile_id: &str,
            request: &PrincipalRequest,
            _cred: &PeerCred,
            _identity: &PeerIdentity,
            _capability_proof: &PrincipalCapabilityProof,
        ) -> Result<PrincipalResponse, ProtocolError> {
            match request {
                PrincipalRequest::Ping => Ok(PrincipalResponse::Pong),
                _ => Ok(PrincipalResponse::Pong),
            }
        }
    }

    fn create_seqpacket_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0 as RawFd; 2];
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0, "socketpair failed: {}", io::Error::last_os_error());
        (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
            OwnedFd::from_raw_fd(fds[1])
        })
    }

    fn my_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    fn my_gid() -> u32 {
        unsafe { libc::getgid() }
    }

    fn pid(id: &str) -> ProfileId {
        ProfileId::new(id).unwrap()
    }

    fn test_capability_proof() -> PrincipalCapabilityProof {
        PrincipalCapabilityProof::from_bytes([0x42u8; CAPABILITY_PROOF_BYTES])
    }

    fn make_profile_map(entries: &[(&str, u32, u32)]) -> BTreeMap<String, ProfileAccess> {
        entries
            .iter()
            .map(|(name, uid, gid)| {
                (
                    name.to_string(),
                    ProfileAccess {
                        expected_uid: *uid,
                        expected_gid: *gid,
                    },
                )
            })
            .collect()
    }

    fn make_test_server(
        profiles: &[(&str, u32, u32)],
    ) -> (IpcServer, Arc<AtomicBool>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let profile_map = make_profile_map(profiles);
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let server = IpcServer::bind(
            runtime_dir,
            profile_map,
            cancel.clone(),
            PathBuf::from("/proc"),
        )
        .unwrap();
        (server, cancel, dir)
    }

    #[test]
    fn test_profile_id_rejects_empty() {
        assert!(ProfileId::new("").is_err());
    }

    #[test]
    fn test_profile_id_rejects_slash() {
        assert!(ProfileId::new("foo/bar").is_err());
    }

    #[test]
    fn test_profile_id_rejects_backslash() {
        assert!(ProfileId::new("foo\\bar").is_err());
    }

    #[test]
    fn test_profile_id_rejects_dot() {
        assert!(ProfileId::new(".").is_err());
    }

    #[test]
    fn test_profile_id_rejects_dotdot() {
        assert!(ProfileId::new("..").is_err());
    }

    #[test]
    fn test_profile_id_accepts_valid() {
        assert!(ProfileId::new("my-profile").is_ok());
        assert!(ProfileId::new("profile_123").is_ok());
        assert!(ProfileId::new("a.b.c").is_ok());
    }

    #[test]
    fn test_runtime_dir_creates_with_correct_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let puid = my_uid();
        let pgid = my_gid();
        let profile_map = make_profile_map(&[("prof-a", puid, pgid)]);
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let base_meta = std::fs::metadata(runtime_dir.base_path()).unwrap();
        assert_eq!(base_meta.permissions().mode() & 0o777, BASE_DIR_MODE);

        let admin_meta = std::fs::metadata(runtime_dir.admin_dir_path()).unwrap();
        assert_eq!(admin_meta.permissions().mode() & 0o777, ADMIN_DIR_MODE);

        let principal_meta = std::fs::metadata(runtime_dir.principal_root_path()).unwrap();
        assert_eq!(
            principal_meta.permissions().mode() & 0o777,
            PRINCIPAL_ROOT_DIR_MODE
        );

        let profile_id = pid("prof-a");
        let profile_meta =
            std::fs::metadata(runtime_dir.profile_dir_path(&profile_id).unwrap()).unwrap();
        assert_eq!(profile_meta.permissions().mode() & 0o777, PROFILE_DIR_MODE);
    }

    #[test]
    fn test_runtime_dir_admin_socket_path() {
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let profile_map = BTreeMap::new();
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();
        assert_eq!(
            runtime_dir.admin_socket_path(),
            dir.path().join(ADMIN_DIR_NAME).join(ADMIN_SOCKET_NAME)
        );
    }

    #[test]
    fn test_runtime_dir_principal_socket_path() {
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let puid = my_uid();
        let pgid = my_gid();
        let profile_map = make_profile_map(&[("my-profile", puid, pgid)]);
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();
        let profile_id = pid("my-profile");
        assert_eq!(
            runtime_dir.principal_socket_path(&profile_id).unwrap(),
            dir.path()
                .join(PRINCIPAL_ROOT_NAME)
                .join("my-profile")
                .join(PROFILE_SOCKET_NAME)
        );
    }

    #[test]
    fn test_server_bind_creates_admin_socket() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        assert!(server.admin_socket_path().exists());
    }

    #[test]
    fn test_server_bind_creates_principal_sockets() {
        if unsafe { libc::geteuid() == 0 } {
            return;
        }
        let puid = my_uid();
        let pgid = my_gid();
        let (server, _cancel, _dir) =
            make_test_server(&[("profile-a", puid, pgid), ("profile-b", puid, pgid)]);
        assert!(
            server
                .principal_socket_path(&pid("profile-a"))
                .unwrap()
                .exists()
        );
        assert!(
            server
                .principal_socket_path(&pid("profile-b"))
                .unwrap()
                .exists()
        );
    }

    #[test]
    fn test_server_socket_permissions_are_correct() {
        let puid = my_uid();
        let pgid = my_gid();
        let (server, _cancel, _dir) = make_test_server(&[("prof", puid, pgid)]);
        use std::os::unix::fs::PermissionsExt;

        let admin_meta = std::fs::metadata(server.admin_socket_path()).unwrap();
        assert_eq!(admin_meta.permissions().mode() & 0o777, ADMIN_SOCK_MODE);

        let prof_meta =
            std::fs::metadata(server.principal_socket_path(&pid("prof")).unwrap()).unwrap();
        assert_eq!(prof_meta.permissions().mode() & 0o777, PROFILE_SOCK_MODE);
    }

    #[test]
    fn test_server_unknown_principal_returns_none() {
        let puid = my_uid();
        let pgid = my_gid();
        let (server, _cancel, _dir) = make_test_server(&[("known", puid, pgid)]);
        assert!(server.principal_socket_path(&pid("unknown")).is_none());
    }

    #[test]
    fn test_duplicate_uid_rejected() {
        if unsafe { libc::geteuid() != 0 } {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let base_uid = my_uid();
        let profile_map =
            make_profile_map(&[("a", base_uid, my_gid()), ("b", base_uid, my_gid() + 1)]);
        let result = RuntimeDir::create(dir.path(), uid, gid, &profile_map);
        assert!(matches!(result, Err(IpcError::DuplicateAccess { .. })));
    }

    #[test]
    fn test_duplicate_gid_rejected() {
        if unsafe { libc::geteuid() != 0 } {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let base_gid = my_gid();
        let profile_map =
            make_profile_map(&[("a", my_uid(), base_gid), ("b", my_uid() + 1, base_gid)]);
        let result = RuntimeDir::create(dir.path(), uid, gid, &profile_map);
        assert!(matches!(result, Err(IpcError::DuplicateAccess { .. })));
    }

    #[test]
    fn test_profile_uid_equal_daemon_uid_rejected() {
        if unsafe { libc::geteuid() != 0 } {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let profile_map = make_profile_map(&[("a", uid, my_gid())]);
        let result = RuntimeDir::create(dir.path(), uid, gid, &profile_map);
        assert!(matches!(result, Err(IpcError::DuplicateAccess { .. })));
    }

    #[test]
    fn test_admin_ping_roundtrip() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = TestAdminHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame).unwrap();

        server.handle_one_admin(server_fd, &handler).unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(response.is_ok());
        assert_eq!(response.seq(), 1);
        assert_eq!(response.role(), Role::Admin);
        match response {
            ResponseFrame::Admin(AdminResponseFrame::Ok { action, .. }) => {
                assert_eq!(action, AdminResponse::Pong);
            }
            _ => panic!("expected Admin Ok"),
        }
    }

    #[test]
    fn test_principal_ping_roundtrip() {
        let puid = my_uid();
        let pgid = my_gid();
        let (server, _cancel, _dir) = make_test_server(&[("my-profile", puid, pgid)]);
        let handler = TestPrincipalHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            42,
            PrincipalRequest::Ping,
            test_capability_proof(),
        ));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame).unwrap();

        let profile_id = pid("my-profile");
        server
            .handle_one_principal(server_fd, &profile_id, &handler)
            .unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(response.is_ok());
        assert_eq!(response.seq(), 42);
        assert_eq!(response.role(), Role::Principal);
        match response {
            ResponseFrame::Principal(PrincipalResponseFrame::Ok { action, .. }) => {
                assert_eq!(*action, PrincipalResponse::Pong);
            }
            _ => panic!("expected Principal Ok"),
        }
    }

    #[test]
    fn test_admin_socket_rejects_principal_frame() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = TestAdminHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let wrong_frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            1,
            PrincipalRequest::Ping,
            test_capability_proof(),
        ));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &wrong_frame).unwrap();

        let result = server.handle_one_admin(server_fd, &handler);
        assert!(matches!(result, Err(IpcError::RoleMismatch { .. })));

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(!response.is_ok());
        assert_eq!(response.role(), Role::Admin);
    }

    #[test]
    fn test_principal_socket_rejects_admin_frame() {
        let puid = my_uid();
        let pgid = my_gid();
        let (server, _cancel, _dir) = make_test_server(&[("prof", puid, pgid)]);
        let handler = TestPrincipalHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let wrong_frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &wrong_frame).unwrap();

        let profile_id = pid("prof");
        let result = server.handle_one_principal(server_fd, &profile_id, &handler);
        assert!(matches!(result, Err(IpcError::RoleMismatch { .. })));

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(!response.is_ok());
        assert_eq!(response.role(), Role::Principal);
    }

    #[test]
    fn test_version_mismatch_rejected() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = TestAdminHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let bad_version_frame = RequestFrame::Admin(AdminRequestFrame {
            v: ProtocolVersion::new(99, 0),
            seq: 1,
            action: AdminRequest::Ping,
        });
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &bad_version_frame).unwrap();

        let result = server.handle_one_admin(server_fd, &handler);
        assert!(matches!(result, Err(IpcError::VersionMismatch(_))));

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(!response.is_ok());
    }

    #[test]
    fn test_malformed_message_rejected() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = TestAdminHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let garbage = b"this is not valid json at all {{{";
        unsafe {
            libc::send(
                client_fd.as_raw_fd(),
                garbage.as_ptr() as *const libc::c_void,
                garbage.len(),
                0,
            );
        }

        let result = server.handle_one_admin(server_fd, &handler);
        assert!(matches!(result, Err(IpcError::Codec(_))));

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(!response.is_ok());
    }

    #[test]
    fn test_oversized_message_rejected() {
        let (client_fd, _server_fd) = create_seqpacket_pair();

        let big = AdminRequest::ListCredentials {
            rp_id: Some("x".repeat(MAX_MESSAGE_SIZE + 100)),
        };
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, big));
        let encode_result = SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame);
        assert!(encode_result.is_err());
    }

    #[test]
    fn test_validation_failure_empty_rp_id() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = TestAdminHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let frame = RequestFrame::Admin(AdminRequestFrame::new(
            1,
            AdminRequest::ListCredentials {
                rp_id: Some(String::new()),
            },
        ));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame).unwrap();

        let result = server.handle_one_admin(server_fd, &handler);
        assert!(matches!(result, Err(IpcError::ValidationFailed(_))));

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(!response.is_ok());
    }

    #[test]
    fn test_peer_cred_validation_same_uid() {
        let (client_fd, server_fd) = create_seqpacket_pair();
        let uid = my_uid();
        let cred = validate_peer_cred(server_fd.as_raw_fd(), uid, None).unwrap();
        assert_eq!(cred.uid, uid);
        let _ = client_fd;
    }

    #[test]
    fn test_peer_cred_validation_wrong_uid() {
        let (_client_fd, server_fd) = create_seqpacket_pair();
        let wrong_uid = if my_uid() == 0 { 65534 } else { 0 };
        let result = validate_peer_cred(server_fd.as_raw_fd(), wrong_uid, None);
        assert!(matches!(result, Err(IpcError::PeerRejected { .. })));
    }

    #[test]
    fn test_peer_cred_validation_gid_match() {
        let (client_fd, server_fd) = create_seqpacket_pair();
        let uid = my_uid();
        let gid = my_gid();
        let cred = validate_peer_cred(server_fd.as_raw_fd(), uid, Some(gid)).unwrap();
        assert_eq!(cred.uid, uid);
        assert_eq!(cred.gid, gid);
        let _ = client_fd;
    }

    #[test]
    fn test_peer_cred_validation_gid_mismatch() {
        let (_client_fd, server_fd) = create_seqpacket_pair();
        let uid = my_uid();
        let wrong_gid = if my_gid() == 0 { 65534 } else { my_gid() + 1 };
        let result = validate_peer_cred(server_fd.as_raw_fd(), uid, Some(wrong_gid));
        assert!(matches!(result, Err(IpcError::PeerRejected { .. })));
    }

    #[test]
    fn test_cancellation_stops_accept() {
        let (server, cancel, _dir) = make_test_server(&[]);
        assert!(!server.is_shutdown());

        cancel.store(true, Ordering::Release);
        assert!(server.is_shutdown());

        let result = server.accept_admin_connection();
        assert!(matches!(result, Err(IpcError::Shutdown)));
    }

    #[test]
    fn test_cancellation_stops_principal_accept() {
        let puid = my_uid();
        let pgid = my_gid();
        let (server, cancel, _dir) = make_test_server(&[("prof", puid, pgid)]);
        cancel.store(true, Ordering::Release);

        let profile_id = pid("prof");
        let result = server.accept_principal_connection(&profile_id);
        assert!(matches!(result, Err(IpcError::Shutdown)));
    }

    #[test]
    fn test_connection_counter_limits() {
        let counter = ConnectionCounter::new(2);

        let g1 = counter.try_acquire().unwrap();
        let g2 = counter.try_acquire().unwrap();
        assert!(counter.try_acquire().is_none());

        drop(g1);
        let g3 = counter.try_acquire().unwrap();
        assert!(counter.try_acquire().is_none());

        drop(g2);
        drop(g3);
        let _g4 = counter.try_acquire().unwrap();
    }

    #[test]
    fn test_one_request_routing_admin() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = TestAdminHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let frame = RequestFrame::Admin(AdminRequestFrame::new(100, AdminRequest::Status));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame).unwrap();

        server.handle_one_admin(server_fd, &handler).unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(response.is_ok());
        assert_eq!(response.seq(), 100);

        match response {
            ResponseFrame::Admin(AdminResponseFrame::Ok { action, .. }) => {
                assert!(matches!(action, AdminResponse::Status(_)));
            }
            _ => panic!("expected Status response"),
        }
    }

    #[test]
    fn test_one_request_routing_principal() {
        let puid = my_uid();
        let pgid = my_gid();
        let (server, _cancel, _dir) = make_test_server(&[("p1", puid, pgid)]);
        let handler = TestPrincipalHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            7,
            PrincipalRequest::Ping,
            test_capability_proof(),
        ));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame).unwrap();

        let profile_id = pid("p1");
        server
            .handle_one_principal(server_fd, &profile_id, &handler)
            .unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(response.is_ok());
        assert_eq!(response.seq(), 7);
    }

    #[test]
    fn test_real_af_unix_seqpacket_admin_via_listener() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = TestAdminHandler;

        let client_fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        assert!(client_fd >= 0);
        let client_owned = unsafe { OwnedFd::from_raw_fd(client_fd) };

        let path = server.admin_socket_path();
        let path_bytes = path.as_os_str().as_encoded_bytes();
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, &b) in path_bytes.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }

        let connect_ret = unsafe {
            libc::connect(
                client_fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert_eq!(
            connect_ret,
            0,
            "connect failed: {}",
            io::Error::last_os_error()
        );

        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        SeqpacketCodec::send_msg(client_fd, &frame).unwrap();

        let server_conn = loop {
            match server.accept_admin_connection() {
                Ok(Some(fd)) => break fd,
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(1)),
                Err(e) => panic!("accept failed: {}", e),
            }
        };

        server.handle_one_admin(server_conn, &handler).unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd).unwrap();
        assert!(response.is_ok());
        assert_eq!(response.role(), Role::Admin);

        let _ = client_owned;
    }

    #[test]
    fn test_real_af_unix_seqpacket_principal_via_listener() {
        let puid = my_uid();
        let pgid = my_gid();
        let (server, _cancel, _dir) = make_test_server(&[("test-prof", puid, pgid)]);
        let handler = TestPrincipalHandler;

        let client_fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        assert!(client_fd >= 0);
        let client_owned = unsafe { OwnedFd::from_raw_fd(client_fd) };

        let profile_id = pid("test-prof");
        let path = server.principal_socket_path(&profile_id).unwrap();
        let path_bytes = path.as_os_str().as_encoded_bytes();
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, &b) in path_bytes.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }

        let connect_ret = unsafe {
            libc::connect(
                client_fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert_eq!(connect_ret, 0);

        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            5,
            PrincipalRequest::Ping,
            test_capability_proof(),
        ));
        SeqpacketCodec::send_msg(client_fd, &frame).unwrap();

        let server_conn = loop {
            match server.accept_principal_connection(&profile_id) {
                Ok(Some(fd)) => break fd,
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(1)),
                Err(e) => panic!("accept failed: {}", e),
            }
        };

        server
            .handle_one_principal(server_conn, &profile_id, &handler)
            .unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd).unwrap();
        assert!(response.is_ok());
        assert_eq!(response.role(), Role::Principal);
        assert_eq!(response.seq(), 5);

        let _ = client_owned;
    }

    #[test]
    fn test_connection_limit_enforced() {
        use std::sync::atomic::AtomicUsize;

        struct BlockingHandler {
            gate: Arc<AtomicUsize>,
        }

        impl AdminHandler for BlockingHandler {
            fn handle_admin(
                &self,
                _request: &AdminRequest,
                _cred: &PeerCred,
                _ctx: &super::AdminRequestContext,
            ) -> Result<AdminResponse, ProtocolError> {
                while self.gate.load(Ordering::Acquire) == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Ok(AdminResponse::Pong)
            }
        }

        let (server, _cancel, _dir) = make_test_server(&[]);
        let server = Arc::new(server);
        let gate = Arc::new(AtomicUsize::new(0));

        let mut pairs = Vec::new();
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            pairs.push(create_seqpacket_pair());
        }

        for (client_fd, _) in &pairs {
            let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
            SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame).unwrap();
        }

        let mut handles = Vec::new();
        for (_client_fd, server_fd) in pairs {
            let srv = Arc::clone(&server);
            let g = gate.clone();
            handles.push(std::thread::spawn(move || {
                let handler = BlockingHandler { gate: g };
                srv.handle_one_admin(server_fd, &handler)
            }));
        }

        std::thread::sleep(std::time::Duration::from_millis(50));

        let extra_pair = create_seqpacket_pair();
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        SeqpacketCodec::send_msg(extra_pair.0.as_raw_fd(), &frame).unwrap();
        let overflow_handler = BlockingHandler { gate: gate.clone() };
        let overflow_result = server.handle_one_admin(extra_pair.1, &overflow_handler);
        assert!(
            matches!(overflow_result, Err(IpcError::ConnectionLimit)),
            "expected ConnectionLimit, got {:?}",
            overflow_result
        );

        gate.store(1, Ordering::Release);

        for h in handles {
            let _ = h.join();
        }
    }

    #[test]
    fn test_ipc_error_display() {
        let e = IpcError::Shutdown;
        assert!(e.to_string().contains("shut down"));

        let e = IpcError::ConnectionLimit;
        assert!(e.to_string().contains("connection limit"));

        let e = IpcError::MessageLimit;
        assert!(e.to_string().contains("message limit"));

        let e = IpcError::RoleMismatch {
            expected: Role::Admin,
            got: Role::Principal,
        };
        assert!(e.to_string().contains("role mismatch"));

        let e = IpcError::PeerRejected {
            reason: "bad uid".into(),
        };
        assert!(e.to_string().contains("bad uid"));

        let e = IpcError::UnsafePath {
            detail: "symlink".into(),
        };
        assert!(e.to_string().contains("unsafe path"));

        let e = IpcError::DuplicateAccess {
            profile: "p".into(),
            detail: "dup".into(),
        };
        assert!(e.to_string().contains("duplicate access"));

        let e = IpcError::PrivilegeInsufficient {
            detail: "no caps".into(),
        };
        assert!(e.to_string().contains("insufficient privileges"));
    }

    #[test]
    fn test_server_drop_cleans_up_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let admin_path;
        let principal_path;
        {
            let uid = my_uid();
            let gid = my_gid();
            let puid = my_uid();
            let pgid = my_gid();
            let profile_map = make_profile_map(&[("p1", puid, pgid)]);
            let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();
            let cancel = Arc::new(AtomicBool::new(false));
            let server =
                IpcServer::bind(runtime_dir, profile_map, cancel, PathBuf::from("/proc")).unwrap();
            admin_path = server.admin_socket_path().to_path_buf();
            let p1 = pid("p1");
            principal_path = server.principal_socket_path(&p1).unwrap();
            assert!(admin_path.exists());
            assert!(principal_path.exists());
        }
        assert!(!admin_path.exists());
    }

    #[test]
    fn test_handler_traits_are_separate_types() {
        fn assert_admin_handler<T: AdminHandler>(_: &T) {}
        fn assert_principal_handler<T: PrincipalHandler>(_: &T) {}

        let admin = TestAdminHandler;
        let principal = TestPrincipalHandler;

        assert_admin_handler(&admin);
        assert_principal_handler(&principal);

        let _ = admin;
        let _ = principal;
    }

    struct ErrorAdminHandler;

    impl AdminHandler for ErrorAdminHandler {
        fn handle_admin(
            &self,
            _request: &AdminRequest,
            _cred: &PeerCred,
            _ctx: &super::AdminRequestContext,
        ) -> Result<AdminResponse, ProtocolError> {
            Err(ProtocolError::new(
                ErrorCode::Internal,
                "handler failure",
                RecommendedAction::Retry,
            ))
        }
    }

    struct ErrorPrincipalHandler;

    impl PrincipalHandler for ErrorPrincipalHandler {
        fn handle_principal(
            &self,
            _profile_id: &str,
            _request: &PrincipalRequest,
            _cred: &PeerCred,
            _identity: &PeerIdentity,
            _capability_proof: &PrincipalCapabilityProof,
        ) -> Result<PrincipalResponse, ProtocolError> {
            Err(ProtocolError::new(
                ErrorCode::Internal,
                "handler failure",
                RecommendedAction::Retry,
            ))
        }
    }

    #[test]
    fn test_admin_handler_error_sends_error_response_with_original_seq() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = ErrorAdminHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let frame = RequestFrame::Admin(AdminRequestFrame::new(99, AdminRequest::Ping));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame).unwrap();

        server.handle_one_admin(server_fd, &handler).unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(!response.is_ok());
        assert_eq!(response.seq(), 99);
        assert_eq!(response.role(), Role::Admin);
        match response {
            ResponseFrame::Admin(AdminResponseFrame::Error { error, .. }) => {
                assert_eq!(error.code, ErrorCode::Internal);
            }
            _ => panic!("expected Admin Error"),
        }
    }

    #[test]
    fn test_principal_handler_error_sends_error_response_with_original_seq() {
        let puid = my_uid();
        let pgid = my_gid();
        let (server, _cancel, _dir) = make_test_server(&[("err-prof", puid, pgid)]);
        let handler = ErrorPrincipalHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            55,
            PrincipalRequest::Ping,
            test_capability_proof(),
        ));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame).unwrap();

        let profile_id = pid("err-prof");
        server
            .handle_one_principal(server_fd, &profile_id, &handler)
            .unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client_fd.as_raw_fd()).unwrap();
        assert!(!response.is_ok());
        assert_eq!(response.seq(), 55);
        assert_eq!(response.role(), Role::Principal);
        match response {
            ResponseFrame::Principal(PrincipalResponseFrame::Error { error, .. }) => {
                assert_eq!(error.code, ErrorCode::Internal);
            }
            _ => panic!("expected Principal Error"),
        }
    }

    #[test]
    fn test_safe_unlink_refuses_non_socket() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("regular.txt");
        std::fs::write(&file_path, "not a socket").unwrap();

        let uid = my_uid();
        safe_unlink_socket(&file_path, uid);

        assert!(file_path.exists());
    }

    #[test]
    fn test_safe_unlink_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "target").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let uid = my_uid();
        safe_unlink_socket(&link, uid);

        assert!(link.exists());
    }

    #[test]
    fn test_safe_unlink_refuses_wrong_owner() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);

        let path_bytes = sock_path.as_os_str().as_encoded_bytes();
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, &b) in path_bytes.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }
        let bind_ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert_eq!(bind_ret, 0);
        unsafe { libc::close(fd) };

        let wrong_uid = if my_uid() == 0 { 65534 } else { my_uid() + 1 };
        safe_unlink_socket(&sock_path, wrong_uid);

        assert!(sock_path.exists());

        safe_unlink_socket(&sock_path, my_uid());
        assert!(!sock_path.exists());
    }

    #[test]
    fn test_principal_access_denied_for_wrong_uid() {
        let puid = my_uid();
        let pgid = my_gid();
        let other_uid = if puid == 0 { 65534 } else { puid + 1 };
        let (server, _cancel, _dir) = make_test_server(&[("prof", other_uid, pgid)]);
        let handler = TestPrincipalHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            1,
            PrincipalRequest::Ping,
            test_capability_proof(),
        ));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame).unwrap();

        let profile_id = pid("prof");
        let result = server.handle_one_principal(server_fd, &profile_id, &handler);
        assert!(matches!(result, Err(IpcError::PeerRejected { .. })));
    }

    #[test]
    fn test_admin_access_denied_for_different_uid() {
        let (_server, _cancel, _dir) = make_test_server(&[]);
        let (_client_fd, server_fd) = create_seqpacket_pair();

        let wrong_uid = if my_uid() == 0 { 65534 } else { 0 };
        let raw_fd = server_fd.as_raw_fd();
        let result = validate_peer_cred(raw_fd, wrong_uid, None);
        assert!(matches!(result, Err(IpcError::PeerRejected { .. })));
    }

    #[test]
    fn test_profile_access_map_required_for_principal() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = TestPrincipalHandler;
        let (_client_fd, server_fd) = create_seqpacket_pair();

        let profile_id = pid("nonexistent");
        let result = server.handle_one_principal(server_fd, &profile_id, &handler);
        assert!(matches!(result, Err(IpcError::Io(_))));
    }

    #[test]
    fn test_runtime_dir_cleanup_removes_profile_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let puid = my_uid();
        let pgid = my_gid();

        let profile_dir_path;
        {
            let profile_map = make_profile_map(&[("test", puid, pgid)]);
            let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();
            let test_id = pid("test");
            profile_dir_path = runtime_dir
                .profile_dir_path(&test_id)
                .unwrap()
                .to_path_buf();
            assert!(profile_dir_path.exists());
        }

        assert!(!profile_dir_path.exists());
    }

    #[test]
    fn test_runtime_dir_cleanup_preserves_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();

        let profile_map = BTreeMap::new();
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();

        let unrelated = dir.path().join("unrelated.txt");
        std::fs::write(&unrelated, "keep me").unwrap();

        runtime_dir.cleanup();

        assert!(unrelated.exists());
    }

    #[test]
    fn test_cross_profile_connect_rejected_by_uid() {
        if unsafe { libc::geteuid() == 0 } {
            return;
        }
        let _uid = my_uid();
        let _gid = my_gid();
        let puid_a = my_uid();
        let pgid_a = my_gid();
        let puid_b = puid_a + 1;
        let pgid_b = pgid_a;
        let (server, _cancel, _dir) =
            make_test_server(&[("alpha", puid_a, pgid_a), ("beta", puid_b, pgid_b)]);
        let handler = TestPrincipalHandler;
        let (client_fd, server_fd) = create_seqpacket_pair();

        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            1,
            PrincipalRequest::Ping,
            test_capability_proof(),
        ));
        SeqpacketCodec::send_msg(client_fd.as_raw_fd(), &frame).unwrap();

        let beta_id = pid("beta");
        let result = server.handle_one_principal(server_fd, &beta_id, &handler);
        assert!(
            matches!(result, Err(IpcError::PeerRejected { .. })),
            "cross-profile connect should be rejected"
        );
    }

    #[test]
    fn test_traversal_in_profile_id_rejected() {
        assert!(ProfileId::new("../etc").is_err());
        assert!(ProfileId::new("foo/../../etc").is_err());
        assert!(ProfileId::new("..").is_err());
        assert!(ProfileId::new(".").is_err());
    }

    #[test]
    fn test_symlink_replaced_socket_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let puid = my_uid();
        let pgid = my_gid();

        let profile_map = make_profile_map(&[("sym-test", puid, pgid)]);
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();

        let sym_id = pid("sym-test");
        let sock_path = runtime_dir.principal_socket_path(&sym_id).unwrap();

        std::fs::remove_file(&sock_path).ok();
        let target = dir.path().join("secret.txt");
        std::fs::write(&target, "secret").unwrap();
        std::os::unix::fs::symlink(&target, &sock_path).unwrap();

        let entry = runtime_dir.profile_dirs.get("sym-test").unwrap();
        safe_unlink_socket_at(entry.dir_fd.as_raw_fd(), PROFILE_SOCKET_NAME, uid);

        assert!(
            std::fs::symlink_metadata(&sock_path).is_ok(),
            "symlink should not be removed by safe_unlink_socket_at"
        );
        assert!(target.exists(), "symlink target must be preserved");
    }

    #[test]
    fn test_stale_non_socket_not_removed_in_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let puid = my_uid();
        let pgid = my_gid();

        let profile_map = make_profile_map(&[("stale-test", puid, pgid)]);
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();

        let _stale_id = pid("stale-test");
        let entry = runtime_dir.profile_dirs.get("stale-test").unwrap();
        let stale_file = entry.sock_path.parent().unwrap().join("stale.txt");
        std::fs::write(&stale_file, "stale data").unwrap();

        runtime_dir.cleanup();

        assert!(
            stale_file.exists(),
            "non-socket stale file should be preserved"
        );
    }

    #[test]
    fn test_profile_dir_permissions_and_ownership() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let puid = my_uid();
        let pgid = my_gid();

        let profile_map = make_profile_map(&[("perm-test", puid, pgid)]);
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();

        let perm_id = pid("perm-test");
        let profile_path = runtime_dir.profile_dir_path(&perm_id).unwrap();
        let meta = std::fs::metadata(profile_path).unwrap();

        assert_eq!(meta.permissions().mode() & 0o777, PROFILE_DIR_MODE);
        assert_eq!(meta.uid(), uid);
        assert_eq!(meta.gid(), pgid);
    }

    #[test]
    fn test_profile_socket_permissions_and_ownership() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let puid = my_uid();
        let pgid = my_gid();

        let profile_map = make_profile_map(&[("sock-perm", puid, pgid)]);
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let server =
            IpcServer::bind(runtime_dir, profile_map, cancel, PathBuf::from("/proc")).unwrap();

        let sock_perm_id = pid("sock-perm");
        let sock_path = server.principal_socket_path(&sock_perm_id).unwrap();
        let meta = std::fs::metadata(&sock_path).unwrap();

        assert_eq!(meta.permissions().mode() & 0o777, PROFILE_SOCK_MODE);
        assert_eq!(meta.uid(), uid);
        assert_eq!(meta.gid(), pgid);
    }

    #[test]
    fn test_principal_root_is_daemon_owned() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();

        let profile_map = BTreeMap::new();
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();

        let meta = std::fs::metadata(runtime_dir.principal_root_path()).unwrap();
        assert_eq!(meta.uid(), uid);
        assert_eq!(meta.gid(), gid);
        assert_eq!(meta.permissions().mode() & 0o777, PRINCIPAL_ROOT_DIR_MODE);
    }

    #[test]
    fn test_principal_root_mode_allows_traverse_not_list() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();

        let profile_map = BTreeMap::new();
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();

        let meta = std::fs::metadata(runtime_dir.principal_root_path()).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o711);
        assert!(mode & 0o100 != 0, "owner must have execute (traverse)");
        assert!(mode & 0o010 != 0, "group must have execute (traverse)");
        assert!(mode & 0o001 != 0, "other must have execute (traverse)");
        assert_eq!(mode & 0o040, 0, "group must not have read (no listing)");
        assert_eq!(mode & 0o004, 0, "other must not have read (no listing)");
    }

    #[test]
    fn test_safe_unlink_at_refuses_non_socket() {
        let dir = tempfile::tempdir().unwrap();
        let dir_fd = open_dir_fd(dir.path()).unwrap();

        std::fs::write(dir.path().join("regular.txt"), "data").unwrap();

        safe_unlink_socket_at(dir_fd.as_raw_fd(), "regular.txt", my_uid());

        assert!(dir.path().join("regular.txt").exists());
    }

    #[test]
    fn test_safe_unlink_at_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let dir_fd = open_dir_fd(dir.path()).unwrap();

        let target = dir.path().join("target.txt");
        std::fs::write(&target, "data").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("link.txt")).unwrap();

        safe_unlink_socket_at(dir_fd.as_raw_fd(), "link.txt", my_uid());

        assert!(dir.path().join("link.txt").exists());
    }

    #[test]
    fn test_path_replacement_attack_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let puid = my_uid();
        let pgid = my_gid();

        let profile_map = make_profile_map(&[("attack", puid, pgid)]);
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();

        let entry = runtime_dir.profile_dirs.get("attack").unwrap();

        let sock_path = &entry.sock_path;
        std::fs::remove_file(sock_path).ok();
        std::fs::write(sock_path, "not a socket").unwrap();

        safe_unlink_socket_at(entry.dir_fd.as_raw_fd(), PROFILE_SOCKET_NAME, uid);

        assert!(
            sock_path.exists(),
            "non-socket should not be removed by safe_unlink_socket_at"
        );
    }

    #[test]
    fn test_deterministic_profile_setup_order() {
        if unsafe { libc::geteuid() == 0 } {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let puid = my_uid();
        let pgid = my_gid();

        let profile_map = make_profile_map(&[
            ("zebra", puid, pgid),
            ("alpha", puid, pgid),
            ("middle", puid, pgid),
        ]);
        let runtime_dir = RuntimeDir::create(dir.path(), uid, gid, &profile_map).unwrap();

        let keys: Vec<&String> = runtime_dir.profile_dirs.keys().collect();
        assert_eq!(keys, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn test_safe_chown_succeeds_with_current_uid_gid() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "test").unwrap();

        let result = safe_chown(&file_path, my_uid(), my_gid());
        assert!(result.is_ok());
    }

    #[test]
    fn test_safe_chown_fails_when_not_root_and_uid_differs() {
        if unsafe { libc::geteuid() == 0 } {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "test").unwrap();

        let different_uid = my_uid() + 1;
        let result = safe_chown(&file_path, different_uid, my_gid());
        assert!(matches!(
            result,
            Err(IpcError::PrivilegeInsufficient { .. })
        ));
    }

    #[test]
    fn test_safe_chown_fails_when_not_root_and_gid_differs() {
        if unsafe { libc::geteuid() == 0 } {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "test").unwrap();

        let different_gid = my_gid() + 1;
        let result = safe_chown(&file_path, my_uid(), different_gid);
        assert!(matches!(
            result,
            Err(IpcError::PrivilegeInsufficient { .. })
        ));
    }

    #[test]
    fn test_runtime_dir_create_fails_when_profile_gid_differs_and_not_root() {
        if unsafe { libc::geteuid() == 0 } {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let uid = my_uid();
        let gid = my_gid();
        let different_gid = gid + 1;
        let profile_map = make_profile_map(&[("prof", uid, different_gid)]);
        let result = RuntimeDir::create(dir.path(), uid, gid, &profile_map);
        assert!(matches!(
            result,
            Err(IpcError::PrivilegeInsufficient { .. })
        ));
    }
}
