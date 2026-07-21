use std::fmt;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use passless_core::agent::ProfileId;
use passless_core::agent::protocol::{
    AdminRequest, AdminRequestFrame, AdminResponse, AdminResponseFrame, CodecError,
    PrincipalCapabilityProof, PrincipalRequest, PrincipalRequestFrame, PrincipalResponse,
    PrincipalResponseFrame, ProtocolError, ProtocolVersion, RequestFrame, ResponseFrame, Role,
    SeqpacketCodec, Validate,
};

use super::launcher::{self, SessionCapability};

const ADMIN_DIR_NAME: &str = "admin";
const ADMIN_SOCKET_NAME: &str = "admin.sock";
const PRINCIPAL_ROOT_NAME: &str = "principal";
const PROFILE_SOCKET_NAME: &str = "sock";
const ENV_RUNTIME_DIR: &str = "PASSLESS_AGENT_RUNTIME_DIR";
const BASE_DIR_MODE: u32 = 0o700;
const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_WAIT_POLL: Duration = Duration::from_millis(100);
const ADMIN_SOCK_MODE: u32 = 0o600;
const PROFILE_SOCK_MODE: u32 = 0o660;

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    Codec(CodecError),
    Protocol(ProtocolError),
    RoleMismatch {
        expected: Role,
        got: Role,
    },
    SeqMismatch {
        expected: u64,
        got: u64,
    },
    VersionMismatch(ProtocolError),
    UnsafePath {
        detail: String,
    },
    NoControlFd,
    WrongSocketType {
        detail: String,
    },
    MissingCapability {
        detail: String,
    },
    Timeout,
    #[cfg(test)]
    Cancelled,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "client I/O error: {}", e),
            Self::Codec(e) => write!(f, "codec error: {}", e),
            Self::Protocol(e) => write!(f, "protocol error: {}", e),
            Self::RoleMismatch { expected, got } => {
                write!(f, "role mismatch: expected {:?}, got {:?}", expected, got)
            }
            Self::SeqMismatch { expected, got } => {
                write!(f, "seq mismatch: expected {}, got {}", expected, got)
            }
            Self::VersionMismatch(e) => write!(f, "version mismatch: {}", e),
            Self::UnsafePath { detail } => write!(f, "unsafe path: {}", detail),
            Self::NoControlFd => write!(f, "CONTROL_FD (fd 3) not available"),
            Self::WrongSocketType { detail } => write!(f, "wrong socket type: {}", detail),
            Self::MissingCapability { detail } => write!(f, "missing capability: {}", detail),
            Self::Timeout => write!(f, "operation timed out"),
            #[cfg(test)]
            Self::Cancelled => write!(f, "operation cancelled"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CodecError> for ClientError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

impl From<ProtocolError> for ClientError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

pub fn resolve_runtime_base() -> Result<PathBuf, ClientError> {
    if let Ok(val) = std::env::var(ENV_RUNTIME_DIR) {
        let p = PathBuf::from(&val);
        if !p.is_absolute() {
            return Err(ClientError::UnsafePath {
                detail: format!("{} must be an absolute path", ENV_RUNTIME_DIR),
            });
        }
        validate_runtime_dir_safe(&p)?;
        return Ok(p);
    }

    if let Some(dir) = dirs::runtime_dir() {
        return Ok(dir.join("agent"));
    }

    let uid = unsafe { libc::getuid() };
    Ok(PathBuf::from(format!("/tmp/passless-agent-{}", uid)).join("agent"))
}

fn validate_runtime_dir_safe(path: &Path) -> Result<(), ClientError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| ClientError::UnsafePath {
        detail: format!("cannot stat {:?}: {}", path, e),
    })?;

    if meta.file_type().is_symlink() {
        return Err(ClientError::UnsafePath {
            detail: format!("{:?} is a symlink", path),
        });
    }

    if !meta.is_dir() {
        return Err(ClientError::UnsafePath {
            detail: format!("{:?} is not a directory", path),
        });
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode != BASE_DIR_MODE {
        return Err(ClientError::UnsafePath {
            detail: format!(
                "{:?} mode is {:o}, expected {:o}",
                path, mode, BASE_DIR_MODE
            ),
        });
    }

    let my_uid = unsafe { libc::getuid() };
    if meta.uid() != my_uid {
        return Err(ClientError::UnsafePath {
            detail: format!(
                "{:?} owned by uid {}, expected uid {}",
                path,
                meta.uid(),
                my_uid
            ),
        });
    }

    Ok(())
}

fn admin_socket_path(base: &Path) -> PathBuf {
    base.join(ADMIN_DIR_NAME).join(ADMIN_SOCKET_NAME)
}

fn principal_socket_path(base: &Path, profile: &str) -> PathBuf {
    base.join(PRINCIPAL_ROOT_NAME)
        .join(profile)
        .join(PROFILE_SOCKET_NAME)
}

fn validate_socket_parent_no_symlink(path: &Path) -> Result<(), ClientError> {
    let parent = path.parent().ok_or_else(|| ClientError::UnsafePath {
        detail: "socket path has no parent".to_string(),
    })?;

    let meta = std::fs::symlink_metadata(parent).map_err(|e| ClientError::UnsafePath {
        detail: format!("cannot stat parent {:?}: {}", parent, e),
    })?;

    if meta.file_type().is_symlink() {
        return Err(ClientError::UnsafePath {
            detail: format!("parent {:?} is a symlink", parent),
        });
    }

    Ok(())
}

fn validate_socket_path_safe(path: &Path, expected_mode: u32) -> Result<(), ClientError> {
    validate_socket_parent_no_symlink(path)?;

    let meta = std::fs::symlink_metadata(path).map_err(|e| ClientError::UnsafePath {
        detail: format!("cannot stat socket {:?}: {}", path, e),
    })?;

    if meta.file_type().is_symlink() {
        return Err(ClientError::UnsafePath {
            detail: format!("{:?} is a symlink", path),
        });
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode != expected_mode {
        return Err(ClientError::UnsafePath {
            detail: format!(
                "{:?} socket mode is {:o}, expected {:o}",
                path, mode, expected_mode
            ),
        });
    }

    Ok(())
}

fn connect_seqpacket(path: &Path) -> Result<OwnedFd, ClientError> {
    let path_bytes = path.as_os_str().as_encoded_bytes();

    if path_bytes.len()
        >= unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
            .sun_path
            .len()
    {
        return Err(ClientError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long for sockaddr_un",
        )));
    }

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(ClientError::Io(io::Error::last_os_error()));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, &b) in path_bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }

    let ret = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(ClientError::Io(io::Error::last_os_error()));
    }

    Ok(owned)
}

fn validate_response_frame(
    frame: &ResponseFrame,
    expected_role: Role,
    expected_seq: u64,
) -> Result<(), ClientError> {
    if frame.role() != expected_role {
        return Err(ClientError::RoleMismatch {
            expected: expected_role,
            got: frame.role(),
        });
    }

    if frame.seq() != expected_seq {
        return Err(ClientError::SeqMismatch {
            expected: expected_seq,
            got: frame.seq(),
        });
    }

    if let Err(pe) = ProtocolVersion::negotiate(frame.version()) {
        return Err(ClientError::VersionMismatch(pe));
    }

    Ok(())
}

fn extract_admin_response(frame: ResponseFrame) -> Result<AdminResponse, ClientError> {
    match frame {
        ResponseFrame::Admin(AdminResponseFrame::Ok { action, .. }) => Ok(action),
        ResponseFrame::Admin(AdminResponseFrame::Error { error, .. }) => {
            Err(ClientError::Protocol(error))
        }
        _ => Err(ClientError::RoleMismatch {
            expected: Role::Admin,
            got: Role::Principal,
        }),
    }
}

fn extract_principal_response(frame: ResponseFrame) -> Result<PrincipalResponse, ClientError> {
    match frame {
        ResponseFrame::Principal(PrincipalResponseFrame::Ok { action, .. }) => Ok(action),
        ResponseFrame::Principal(PrincipalResponseFrame::Error { error, .. }) => {
            Err(ClientError::Protocol(error))
        }
        _ => Err(ClientError::RoleMismatch {
            expected: Role::Principal,
            got: Role::Admin,
        }),
    }
}

pub struct AdminClient {
    fd: OwnedFd,
    seq: u64,
}

impl AdminClient {
    pub fn connect(base: &Path) -> Result<Self, ClientError> {
        let sock = admin_socket_path(base);
        validate_socket_path_safe(&sock, ADMIN_SOCK_MODE)?;
        let fd = connect_seqpacket(&sock)?;
        Ok(Self { fd, seq: 0 })
    }

    #[cfg(test)]
    pub fn connect_raw(fd: OwnedFd) -> Self {
        Self { fd, seq: 0 }
    }

    pub fn request(&mut self, action: AdminRequest) -> Result<AdminResponse, ClientError> {
        action
            .validate()
            .map_err(|ve| ClientError::Protocol(ProtocolError::malformed(ve.to_string())))?;

        self.seq = self.seq.checked_add(1).ok_or_else(|| {
            ClientError::Protocol(ProtocolError::malformed("sequence number overflow"))
        })?;
        let seq = self.seq;

        let frame = RequestFrame::Admin(AdminRequestFrame::new(seq, action));
        SeqpacketCodec::send_msg(self.fd.as_raw_fd(), &frame)?;

        let response: ResponseFrame = SeqpacketCodec::recv_msg(self.fd.as_raw_fd())?;
        validate_response_frame(&response, Role::Admin, seq)?;
        extract_admin_response(response)
    }

    pub fn launch_principal_with_stdio(
        &mut self,
        profile_id: &ProfileId,
        command: Vec<String>,
        stdin_fd: std::os::unix::io::RawFd,
        stdout_fd: std::os::unix::io::RawFd,
        stderr_fd: std::os::unix::io::RawFd,
    ) -> Result<AdminResponse, ClientError> {
        let action = AdminRequest::LaunchPrincipal {
            profile_id: profile_id.clone(),
            command,
        };
        action
            .validate()
            .map_err(|ve| ClientError::Protocol(ProtocolError::malformed(ve.to_string())))?;

        self.seq = self.seq.checked_add(1).ok_or_else(|| {
            ClientError::Protocol(ProtocolError::malformed("sequence number overflow"))
        })?;
        let seq = self.seq;

        let frame = RequestFrame::Admin(AdminRequestFrame::new(seq, action));
        let fds = [stdin_fd, stdout_fd, stderr_fd];
        SeqpacketCodec::send_msg_with_fds(self.fd.as_raw_fd(), &frame, &fds)?;

        let response: ResponseFrame = SeqpacketCodec::recv_msg(self.fd.as_raw_fd())?;
        validate_response_frame(&response, Role::Admin, seq)?;
        extract_admin_response(response)
    }

    pub fn wait_principal(
        &mut self,
        session_id: &passless_core::agent::PrincipalSessionId,
        timeout_ms: u32,
    ) -> Result<AdminResponse, ClientError> {
        let action = AdminRequest::WaitPrincipal {
            session_id: session_id.clone(),
            timeout_ms,
        };
        self.request(action)
    }

    pub fn terminate_principal(
        &mut self,
        profile_id: &ProfileId,
    ) -> Result<AdminResponse, ClientError> {
        let action = AdminRequest::TerminatePrincipal {
            profile_id: profile_id.clone(),
        };
        self.request(action)
    }
}

pub struct PrincipalClient {
    fd: OwnedFd,
    seq: u64,
    proof: PrincipalCapabilityProof,
}

impl PrincipalClient {
    pub fn connect_launched(base: &Path, profile: &str) -> Result<Self, ClientError> {
        let control_fd = launcher::CONTROL_FD;

        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstat(control_fd, &mut stat) };
        if ret < 0 {
            return Err(ClientError::NoControlFd);
        }
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFSOCK {
            return Err(ClientError::WrongSocketType {
                detail: format!(
                    "CONTROL_FD is mode {:o}, expected SEQPACKET socket",
                    stat.st_mode & libc::S_IFMT
                ),
            });
        }

        let sock_type = unsafe {
            let mut t: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let r = libc::getsockopt(
                control_fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut t as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            );
            if r < 0 {
                return Err(ClientError::WrongSocketType {
                    detail: "getsockopt SO_TYPE failed".to_string(),
                });
            }
            t
        };
        if sock_type != libc::SOCK_SEQPACKET {
            return Err(ClientError::WrongSocketType {
                detail: format!(
                    "CONTROL_FD socket type is {}, expected SOCK_SEQPACKET",
                    sock_type
                ),
            });
        }

        let capability =
            launcher::peek_capability(control_fd).map_err(|e| ClientError::MissingCapability {
                detail: format!("peek_capability failed: {}", e),
            })?;
        let proof = Self::capability_to_proof(capability);

        let sock = principal_socket_path(base, profile);
        validate_socket_path_safe(&sock, PROFILE_SOCK_MODE)?;
        let fd = connect_seqpacket(&sock)?;

        Ok(Self { fd, seq: 0, proof })
    }

    #[cfg(test)]
    pub fn connect_with_proof(fd: OwnedFd, proof: PrincipalCapabilityProof) -> Self {
        Self { fd, seq: 0, proof }
    }

    fn capability_to_proof(cap: SessionCapability) -> PrincipalCapabilityProof {
        let bytes = *cap.as_bytes();
        PrincipalCapabilityProof::from_bytes(bytes)
    }

    pub fn request(&mut self, action: PrincipalRequest) -> Result<PrincipalResponse, ClientError> {
        action
            .validate()
            .map_err(|ve| ClientError::Protocol(ProtocolError::malformed(ve.to_string())))?;

        self.seq = self.seq.checked_add(1).ok_or_else(|| {
            ClientError::Protocol(ProtocolError::malformed("sequence number overflow"))
        })?;
        let seq = self.seq;

        let frame =
            RequestFrame::Principal(PrincipalRequestFrame::new(seq, action, self.proof.clone()));
        SeqpacketCodec::send_msg(self.fd.as_raw_fd(), &frame)?;

        let response: ResponseFrame = SeqpacketCodec::recv_msg(self.fd.as_raw_fd())?;
        validate_response_frame(&response, Role::Principal, seq)?;
        extract_principal_response(response)
    }
}

pub enum WaitTarget {
    Intent,
    Delegation,
}

pub fn wait_with_poll<F>(
    target: WaitTarget,
    request_id: &passless_core::agent::PendingRequestId,
    timeout: Option<Duration>,
    poll_interval: Option<Duration>,
    mut poll_fn: F,
) -> Result<(), ClientError>
where
    F: FnMut() -> Result<bool, ClientError>,
{
    let deadline = Instant::now()
        .checked_add(timeout.unwrap_or(DEFAULT_WAIT_TIMEOUT))
        .ok_or(ClientError::Timeout)?;
    let interval = poll_interval.unwrap_or(DEFAULT_WAIT_POLL);

    let _ = target;
    let _ = request_id;

    loop {
        if Instant::now() >= deadline {
            return Err(ClientError::Timeout);
        }

        if poll_fn()? {
            return Ok(());
        }

        cancellation_safe_sleep(interval, deadline)?;
    }
}

fn cancellation_safe_sleep(duration: Duration, deadline: Instant) -> Result<(), ClientError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .unwrap_or(Duration::ZERO);
    let sleep_dur = duration.min(remaining);
    if sleep_dur.is_zero() {
        return Err(ClientError::Timeout);
    }
    std::thread::sleep(sleep_dur);
    if Instant::now() >= deadline {
        return Err(ClientError::Timeout);
    }
    Ok(())
}

#[cfg(test)]
pub fn admin_socket_addr(base: &Path) -> PathBuf {
    admin_socket_path(base)
}

#[cfg(test)]
pub fn principal_socket_addr(base: &Path, profile: &str) -> PathBuf {
    principal_socket_path(base, profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use passless_core::agent::protocol::{CAPABILITY_PROOF_BYTES, PrincipalResponseFrame};
    use passless_core::agent::{DaemonStatus, ProfileId};

    use crate::agent::ipc::{AdminHandler, IpcServer, PrincipalHandler, ProfileAccess, RuntimeDir};

    struct EchoAdminHandler;

    impl AdminHandler for EchoAdminHandler {
        fn handle_admin(
            &self,
            request: &AdminRequest,
            _cred: &passless_core::agent::PeerCred,
            _ctx: &crate::agent::ipc::AdminRequestContext,
        ) -> Result<AdminResponse, ProtocolError> {
            match request {
                AdminRequest::Ping => Ok(AdminResponse::Pong),
                AdminRequest::Status => Ok(AdminResponse::Status(DaemonStatus {
                    daemon_version: "test".into(),
                    protocol_version: passless_core::agent::CURRENT_VERSION,
                    backend: "test".into(),
                    uptime_secs: 0,
                    credential_count: 0,
                })),
                _ => Ok(AdminResponse::Pong),
            }
        }
    }

    struct EchoPrincipalHandler;

    impl PrincipalHandler for EchoPrincipalHandler {
        fn handle_principal(
            &self,
            _profile_id: &str,
            request: &PrincipalRequest,
            _cred: &passless_core::agent::PeerCred,
            _identity: &super::launcher::PeerIdentity,
            _capability_proof: &PrincipalCapabilityProof,
        ) -> Result<PrincipalResponse, ProtocolError> {
            match request {
                PrincipalRequest::Ping => Ok(PrincipalResponse::Pong),
                _ => Ok(PrincipalResponse::Pong),
            }
        }
    }

    fn my_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    fn my_gid() -> u32 {
        unsafe { libc::getgid() }
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
            std::path::PathBuf::from("/proc"),
        )
        .unwrap();
        (server, cancel, dir)
    }

    fn connect_client_to_admin_socket(server: &IpcServer) -> OwnedFd {
        let path = server.admin_socket_path();
        connect_seqpacket(path).unwrap()
    }

    fn connect_client_to_principal_socket(server: &IpcServer, profile: &str) -> OwnedFd {
        let pid = ProfileId::new(profile).unwrap();
        let path = server.principal_socket_path(&pid).unwrap();
        connect_seqpacket(&path).unwrap()
    }

    fn test_proof() -> PrincipalCapabilityProof {
        PrincipalCapabilityProof::from_bytes([0x42u8; CAPABILITY_PROOF_BYTES])
    }

    #[test]
    fn test_admin_round_trip_via_client() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = EchoAdminHandler;
        let client_fd = connect_client_to_admin_socket(&server);
        let mut client = AdminClient::connect_raw(client_fd);

        let server_conn = loop {
            match server.accept_admin_connection() {
                Ok(Some(fd)) => break fd,
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(e) => panic!("accept failed: {}", e),
            }
        };

        let resp = std::thread::spawn(move || {
            server.handle_one_admin(server_conn, &handler).unwrap();
        });

        let result = client.request(AdminRequest::Ping).unwrap();
        assert_eq!(result, AdminResponse::Pong);

        resp.join().unwrap();
    }

    #[test]
    fn test_admin_status_round_trip() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = EchoAdminHandler;
        let client_fd = connect_client_to_admin_socket(&server);
        let mut client = AdminClient::connect_raw(client_fd);

        let server_conn = loop {
            match server.accept_admin_connection() {
                Ok(Some(fd)) => break fd,
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(e) => panic!("accept failed: {}", e),
            }
        };

        let resp = std::thread::spawn(move || {
            server.handle_one_admin(server_conn, &handler).unwrap();
        });

        let result = client.request(AdminRequest::Status).unwrap();
        assert!(matches!(result, AdminResponse::Status(_)));

        resp.join().unwrap();
    }

    #[test]
    fn test_admin_monotonic_seq() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let handler = EchoAdminHandler;
        let client_fd = connect_client_to_admin_socket(&server);
        let mut client = AdminClient::connect_raw(client_fd);

        let server_conn = loop {
            match server.accept_admin_connection() {
                Ok(Some(fd)) => break fd,
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(e) => panic!("accept failed: {}", e),
            }
        };

        let resp = std::thread::spawn(move || {
            server.handle_one_admin(server_conn, &handler).unwrap();
        });

        let _ = client.request(AdminRequest::Ping).unwrap();
        assert_eq!(client.seq, 1);

        resp.join().unwrap();
    }

    #[test]
    fn test_principal_round_trip_with_injected_proof() {
        let puid = my_uid();
        let pgid = my_gid();
        let (server, _cancel, _dir) = make_test_server(&[("test-prof", puid, pgid)]);
        let handler = EchoPrincipalHandler;
        let client_fd = connect_client_to_principal_socket(&server, "test-prof");
        let proof = test_proof();
        let mut client = PrincipalClient::connect_with_proof(client_fd, proof);

        let profile_id = ProfileId::new("test-prof").unwrap();
        let server_conn = loop {
            match server.accept_principal_connection(&profile_id) {
                Ok(Some(fd)) => break fd,
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(e) => panic!("accept failed: {}", e),
            }
        };

        let resp = std::thread::spawn(move || {
            server
                .handle_one_principal(server_conn, &profile_id, &handler)
                .unwrap();
        });

        let result = client.request(PrincipalRequest::Ping).unwrap();
        assert_eq!(result, PrincipalResponse::Pong);

        resp.join().unwrap();
    }

    #[test]
    fn test_admin_wrong_role_response_rejected() {
        let (_server, _cancel, _dir) = make_test_server(&[]);
        let (client_fd, server_fd) = {
            let mut fds = [0 as std::os::unix::io::RawFd; 2];
            let ret = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            assert_eq!(ret, 0);
            (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
                OwnedFd::from_raw_fd(fds[1])
            })
        };
        let mut client = AdminClient::connect_raw(client_fd);

        let resp = std::thread::spawn(move || {
            let wrong_response =
                ResponseFrame::Principal(PrincipalResponseFrame::ok(1, PrincipalResponse::Pong));
            SeqpacketCodec::send_msg(server_fd.as_raw_fd(), &wrong_response).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        client.seq = 0;
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        SeqpacketCodec::send_msg(client.fd.as_raw_fd(), &frame).unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client.fd.as_raw_fd()).unwrap();
        let err = validate_response_frame(&response, Role::Admin, 1);
        assert!(matches!(err, Err(ClientError::RoleMismatch { .. })));

        resp.join().unwrap();
    }

    #[test]
    fn test_admin_wrong_seq_response_rejected() {
        let (client_fd, server_fd) = {
            let mut fds = [0 as std::os::unix::io::RawFd; 2];
            let ret = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            assert_eq!(ret, 0);
            (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
                OwnedFd::from_raw_fd(fds[1])
            })
        };
        let mut client = AdminClient::connect_raw(client_fd);

        let resp = std::thread::spawn(move || {
            let wrong_seq_response =
                ResponseFrame::Admin(AdminResponseFrame::ok(999, AdminResponse::Pong));
            SeqpacketCodec::send_msg(server_fd.as_raw_fd(), &wrong_seq_response).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        client.seq = 0;
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        SeqpacketCodec::send_msg(client.fd.as_raw_fd(), &frame).unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client.fd.as_raw_fd()).unwrap();
        let err = validate_response_frame(&response, Role::Admin, 1);
        assert!(matches!(err, Err(ClientError::SeqMismatch { .. })));

        resp.join().unwrap();
    }

    #[test]
    fn test_admin_version_mismatch_response_rejected() {
        let (client_fd, server_fd) = {
            let mut fds = [0 as std::os::unix::io::RawFd; 2];
            let ret = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            assert_eq!(ret, 0);
            (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
                OwnedFd::from_raw_fd(fds[1])
            })
        };
        let mut client = AdminClient::connect_raw(client_fd);

        let resp = std::thread::spawn(move || {
            let bad_version_response = ResponseFrame::Admin(AdminResponseFrame::Ok {
                v: ProtocolVersion::new(99, 0),
                seq: 1,
                action: AdminResponse::Pong,
            });
            SeqpacketCodec::send_msg(server_fd.as_raw_fd(), &bad_version_response).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        client.seq = 0;
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        SeqpacketCodec::send_msg(client.fd.as_raw_fd(), &frame).unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client.fd.as_raw_fd()).unwrap();
        let err = validate_response_frame(&response, Role::Admin, 1);
        assert!(matches!(err, Err(ClientError::VersionMismatch(_))));

        resp.join().unwrap();
    }

    #[test]
    fn test_admin_error_response_surfaces_protocol_error() {
        let (client_fd, server_fd) = {
            let mut fds = [0 as std::os::unix::io::RawFd; 2];
            let ret = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            assert_eq!(ret, 0);
            (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
                OwnedFd::from_raw_fd(fds[1])
            })
        };
        let mut client = AdminClient::connect_raw(client_fd);

        let resp = std::thread::spawn(move || {
            let err_response = ResponseFrame::Admin(AdminResponseFrame::error(
                1,
                ProtocolError::new(
                    passless_core::agent::ErrorCode::Internal,
                    "boom",
                    passless_core::agent::RecommendedAction::Retry,
                ),
            ));
            SeqpacketCodec::send_msg(server_fd.as_raw_fd(), &err_response).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        client.seq = 0;
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        SeqpacketCodec::send_msg(client.fd.as_raw_fd(), &frame).unwrap();

        let response: ResponseFrame = SeqpacketCodec::recv_msg(client.fd.as_raw_fd()).unwrap();
        validate_response_frame(&response, Role::Admin, 1).unwrap();
        let result = extract_admin_response(response);
        assert!(matches!(result, Err(ClientError::Protocol(_))));

        resp.join().unwrap();
    }

    #[test]
    fn test_resolve_runtime_base_default() {
        unsafe { std::env::remove_var(ENV_RUNTIME_DIR) };
        let base = resolve_runtime_base().unwrap();
        assert!(base.is_absolute(), "base must be absolute: {:?}", base);
    }

    #[test]
    fn test_resolve_runtime_base_rejects_relative() {
        unsafe { std::env::set_var(ENV_RUNTIME_DIR, "relative/path") };
        let result = resolve_runtime_base();
        assert!(matches!(result, Err(ClientError::UnsafePath { .. })));
        unsafe { std::env::remove_var(ENV_RUNTIME_DIR) };
    }

    #[test]
    fn test_resolve_runtime_base_accepts_valid_dir() {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        unsafe { std::env::set_var(ENV_RUNTIME_DIR, dir.path().to_str().unwrap()) };
        let result = resolve_runtime_base();
        assert!(result.is_ok());
        unsafe { std::env::remove_var(ENV_RUNTIME_DIR) };
    }

    #[test]
    fn test_resolve_runtime_base_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        unsafe { std::env::set_var(ENV_RUNTIME_DIR, link.to_str().unwrap()) };
        let result = resolve_runtime_base();
        assert!(matches!(result, Err(ClientError::UnsafePath { .. })));
        unsafe { std::env::remove_var(ENV_RUNTIME_DIR) };
    }

    #[test]
    fn test_resolve_runtime_base_rejects_wrong_mode() {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        unsafe { std::env::set_var(ENV_RUNTIME_DIR, dir.path().to_str().unwrap()) };
        let result = resolve_runtime_base();
        assert!(matches!(result, Err(ClientError::UnsafePath { .. })));
        unsafe { std::env::remove_var(ENV_RUNTIME_DIR) };
    }

    #[test]
    fn test_socket_path_symlink_parent_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let fake_sock = link.join("admin.sock");
        let result = validate_socket_parent_no_symlink(&fake_sock);
        assert!(matches!(result, Err(ClientError::UnsafePath { .. })));
    }

    #[test]
    fn test_socket_path_symlink_socket_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.sock");

        let fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);

        let path_bytes = target.as_os_str().as_encoded_bytes();
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

        let link = dir.path().join("link.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = validate_socket_path_safe(&link, 0o600);
        assert!(matches!(result, Err(ClientError::UnsafePath { .. })));
    }

    #[test]
    fn test_socket_path_wrong_mode_rejected() {
        let (server, _cancel, _dir) = make_test_server(&[]);
        let sock = server.admin_socket_path();

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o660)).unwrap();

        let result = validate_socket_path_safe(sock, 0o600);
        assert!(matches!(result, Err(ClientError::UnsafePath { .. })));
    }

    #[test]
    fn test_oversized_response_rejected_by_codec() {
        let (client_fd, server_fd) = {
            let mut fds = [0 as std::os::unix::io::RawFd; 2];
            let ret = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            assert_eq!(ret, 0);
            (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
                OwnedFd::from_raw_fd(fds[1])
            })
        };
        let mut client = AdminClient::connect_raw(client_fd);

        client.seq = 0;
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        SeqpacketCodec::send_msg(client.fd.as_raw_fd(), &frame).unwrap();

        let resp = std::thread::spawn(move || {
            let big = "x".repeat(passless_core::agent::MAX_MESSAGE_SIZE + 100);
            let oversized = ResponseFrame::Admin(AdminResponseFrame::error(
                1,
                ProtocolError::new(
                    passless_core::agent::ErrorCode::Internal,
                    big,
                    passless_core::agent::RecommendedAction::Abort,
                ),
            ));
            let encode_result = SeqpacketCodec::send_msg(server_fd.as_raw_fd(), &oversized);
            assert!(encode_result.is_err());
        });

        let result = client.request(AdminRequest::Ping);
        assert!(result.is_err());

        resp.join().unwrap();
    }

    #[test]
    fn test_wait_with_poll_immediate_success() {
        let req_id = passless_core::agent::PendingRequestId::new();
        let result = wait_with_poll(
            WaitTarget::Intent,
            &req_id,
            Some(Duration::from_secs(5)),
            Some(Duration::from_millis(10)),
            || Ok(true),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_wait_with_poll_timeout() {
        let req_id = passless_core::agent::PendingRequestId::new();
        let result = wait_with_poll(
            WaitTarget::Delegation,
            &req_id,
            Some(Duration::from_millis(50)),
            Some(Duration::from_millis(10)),
            || Ok(false),
        );
        assert!(matches!(result, Err(ClientError::Timeout)));
    }

    #[test]
    fn test_wait_with_poll_eventual_success() {
        let req_id = passless_core::agent::PendingRequestId::new();
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter_clone = counter.clone();
        let result = wait_with_poll(
            WaitTarget::Intent,
            &req_id,
            Some(Duration::from_secs(5)),
            Some(Duration::from_millis(10)),
            move || {
                let n = counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(n >= 2)
            },
        );
        assert!(result.is_ok());
        assert!(counter.load(Ordering::SeqCst) >= 3);
    }

    #[test]
    fn test_client_error_display() {
        let e = ClientError::NoControlFd;
        assert!(e.to_string().contains("CONTROL_FD"));

        let e = ClientError::Timeout;
        assert!(e.to_string().contains("timed out"));

        let e = ClientError::RoleMismatch {
            expected: Role::Admin,
            got: Role::Principal,
        };
        assert!(e.to_string().contains("role mismatch"));

        let e = ClientError::SeqMismatch {
            expected: 1,
            got: 2,
        };
        assert!(e.to_string().contains("seq mismatch"));

        let e = ClientError::WrongSocketType {
            detail: "bad type".into(),
        };
        assert!(e.to_string().contains("wrong socket type"));

        let e = ClientError::MissingCapability {
            detail: "no cap".into(),
        };
        assert!(e.to_string().contains("missing capability"));

        let e = ClientError::Cancelled;
        assert!(e.to_string().contains("cancelled"));
    }

    #[test]
    fn test_admin_path_construction() {
        let base = Path::new("/run/user/1000/agent");
        assert_eq!(
            admin_socket_addr(base),
            PathBuf::from("/run/user/1000/agent/admin/admin.sock")
        );
    }

    #[test]
    fn test_principal_path_construction() {
        let base = Path::new("/run/user/1000/agent");
        assert_eq!(
            principal_socket_addr(base, "my-profile"),
            PathBuf::from("/run/user/1000/agent/principal/my-profile/sock")
        );
    }

    #[test]
    fn test_capability_to_proof_conversion() {
        let cap = SessionCapability::from_bytes([0xAB; 32]);
        let proof = PrincipalClient::capability_to_proof(cap);
        assert_eq!(proof.as_bytes(), &[0xAB; 32]);
    }

    #[test]
    fn test_type_safety_admin_cannot_send_principal() {
        fn assert_admin_request(_: AdminRequest) {}
        fn assert_principal_request(_: PrincipalRequest) {}

        assert_admin_request(AdminRequest::Ping);
        assert_principal_request(PrincipalRequest::Ping);
    }
}
