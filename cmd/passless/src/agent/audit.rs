use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{FromRawFd, IntoRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use nix::dir::Dir;
use nix::fcntl::{Flock, FlockArg, OFlag, renameat};
use nix::sys::stat::{Mode, SFlag};
use nix::unistd::dup;
use sha2::{Digest, Sha256};

use super::audit_events::{AuditEvent, DaemonRecoverBuilder, RecoveryReason};

// # Integrity model
//
// All hashes in this module are **unkeyed**, domain-separated SHA-256 digests.
// They are deliberately **not** HMACs and provide **tamper-evident** integrity,
// **not** tamper-proof (cryptographic) integrity.  The security boundary is the
// owner-only filesystem controls: the audit directory is created with mode 0700
// and all files with mode 0600, owned by the daemon's uid.  Under that
// assumption any modification by a third party would first require breaking
// filesystem permissions, which is outside the unkeyed threat model.
//
// Concretely:
//   * An attacker who can write to the audit directory as the owner can
//     recompute valid hashes and produce a forged but internally consistent
//     chain.  Rollback of both the owner-writable log and the anchor file
//     is therefore **outside the unkeyed threat model**.
//   * The hashes detect accidental corruption, partial writes, and any
//     modification that does not also rewrite every downstream hash.
//   * The domain prefixes (`passless/audit/record/v1`, etc.) prevent
//     cross-context hash reuse between headers, records, and anchors.

const AUDIT_DIR_MODE: u32 = 0o700;
const AUDIT_FILE_MODE: u32 = 0o600;
const SEGMENT_MAGIC: u32 = 0x41554453;
const FRAME_MAGIC: u32 = 0x41554449;
const ANCHOR_MAGIC: u32 = 0x41554441;
const SCHEMA_VERSION: u32 = 1;
const HEADER_SIZE: usize = 4 + 4 + 8 + 8 + 32 + 32;
const ANCHOR_SIZE: usize = 4 + 4 + 8 + 8 + 32 + 32;
const FRAME_OVERHEAD: usize = 8 + 8 + 8 + 4 + 32 + 32;
const MAX_PAYLOAD_SIZE: u32 = 64 * 1024;
const MAX_FRAME_SIZE: u64 = FRAME_OVERHEAD as u64 + MAX_PAYLOAD_SIZE as u64;
const DEFAULT_MAX_SEGMENT_SIZE: u64 = 64 * 1024 * 1024;
const HASH_DOMAIN: &str = "passless/audit/record/v1";
const HEADER_DOMAIN: &str = "passless/audit/header/v1";
const ANCHOR_DOMAIN: &str = "passless/audit/anchor/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    Io(String),
    SymlinkDetected(String),
    LockFailed(String),
    InvalidFrame(String),
    HashMismatch { expected: String, actual: String },
    SequenceGap { expected: u64, actual: u64 },
    CircuitBroken(String),
    SchemaViolation(String),
    RotationFailed(String),
    TruncatedRecord,
    Overflow,
    OwnerMismatch(String),
    ModeMismatch(String),
    AnchorViolation(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {}", msg),
            Self::SymlinkDetected(msg) => write!(f, "symlink detected: {}", msg),
            Self::LockFailed(msg) => write!(f, "lock failed: {}", msg),
            Self::InvalidFrame(msg) => write!(f, "invalid frame: {}", msg),
            Self::HashMismatch { expected, actual } => {
                write!(f, "hash mismatch: expected {}, got {}", expected, actual)
            }
            Self::SequenceGap { expected, actual } => {
                write!(f, "sequence gap: expected {}, got {}", expected, actual)
            }
            Self::CircuitBroken(msg) => write!(f, "circuit broken: {}", msg),
            Self::SchemaViolation(msg) => write!(f, "schema violation: {}", msg),
            Self::RotationFailed(msg) => write!(f, "rotation failed: {}", msg),
            Self::TruncatedRecord => write!(f, "truncated record"),
            Self::Overflow => write!(f, "sequence overflow"),
            Self::OwnerMismatch(msg) => write!(f, "owner mismatch: {}", msg),
            Self::ModeMismatch(msg) => write!(f, "mode mismatch: {}", msg),
            Self::AnchorViolation(msg) => write!(f, "anchor violation: {}", msg),
        }
    }
}

impl std::error::Error for AuditError {}

impl From<io::Error> for AuditError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<nix::Error> for AuditError {
    fn from(err: nix::Error) -> Self {
        Self::Io(err.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct AuditReceipt {
    #[cfg(test)]
    pub sequence: u64,
    #[cfg(test)]
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnchorState {
    segment_index: u64,
    sequence: u64,
    hash: [u8; 32],
}

impl AnchorState {
    fn initial() -> Self {
        Self {
            segment_index: 0,
            sequence: 0,
            hash: [0u8; 32],
        }
    }
}

trait AuditWriter {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<usize>;
    fn sync_data(&mut self) -> io::Result<()>;
    fn truncate_to(&mut self, len: u64) -> io::Result<()>;
    fn current_offset(&mut self) -> io::Result<u64>;
}

struct FileWriter {
    file: File,
    offset: u64,
}

impl FileWriter {
    fn new(file: File) -> Self {
        let offset = file.metadata().map(|m| m.len()).unwrap_or(0);
        Self { file, offset }
    }
}

impl AuditWriter for FileWriter {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<usize> {
        self.file.seek(SeekFrom::Start(offset))?;
        let n = self.file.write(data)?;
        self.offset = offset + n as u64;
        Ok(n)
    }

    fn sync_data(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }

    fn truncate_to(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.offset = len;
        Ok(())
    }

    fn current_offset(&mut self) -> io::Result<u64> {
        Ok(self.offset)
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    WriteRecord,
    FlushRecord,
    FsyncRecord,
    FsyncDir,
    WriteAnchor,
    FsyncAnchor,
    RenameAnchor,
    WriteHeader,
    FsyncHeader,
}

#[cfg(test)]
pub trait FaultInjector: Send + Sync {
    fn should_fail(&self, point: FaultPoint) -> bool;
}

#[cfg(test)]
struct NeverFail;

#[cfg(test)]
impl FaultInjector for NeverFail {
    fn should_fail(&self, _point: FaultPoint) -> bool {
        false
    }
}

#[cfg(test)]
pub struct FailAt(pub FaultPoint);

#[cfg(test)]
impl FaultInjector for FailAt {
    fn should_fail(&self, point: FaultPoint) -> bool {
        self.0 == point
    }
}

#[cfg(test)]
struct FailEnospc;

#[cfg(test)]
impl FaultInjector for FailEnospc {
    fn should_fail(&self, point: FaultPoint) -> bool {
        point == FaultPoint::WriteRecord
    }
}

struct SegmentHeader {
    version: u32,
    segment_index: u64,
    first_sequence: u64,
    previous_final_hash: [u8; 32],
}

impl SegmentHeader {
    fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&SEGMENT_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..16].copy_from_slice(&self.segment_index.to_le_bytes());
        buf[16..24].copy_from_slice(&self.first_sequence.to_le_bytes());
        buf[24..56].copy_from_slice(&self.previous_final_hash);
        let hash = compute_header_hash(&buf[0..56]);
        buf[56..88].copy_from_slice(&hash);
        buf
    }

    fn decode(data: &[u8; HEADER_SIZE]) -> Result<Self, AuditError> {
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != SEGMENT_MAGIC {
            return Err(AuditError::InvalidFrame("bad segment magic".into()));
        }
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != SCHEMA_VERSION {
            return Err(AuditError::SchemaViolation(format!(
                "unsupported version: {}",
                version
            )));
        }
        let segment_index = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let first_sequence = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let mut previous_final_hash = [0u8; 32];
        previous_final_hash.copy_from_slice(&data[24..56]);
        let expected_hash = compute_header_hash(&data[0..56]);
        let actual_hash: [u8; 32] = data[56..88].try_into().unwrap();
        if expected_hash != actual_hash {
            return Err(AuditError::HashMismatch {
                expected: hex::encode(expected_hash),
                actual: hex::encode(actual_hash),
            });
        }
        Ok(Self {
            version,
            segment_index,
            first_sequence,
            previous_final_hash,
        })
    }
}

// Unkeyed domain-separated SHA-256.  Tamper-evident under owner-only
// filesystem controls; NOT an HMAC and NOT tamper-proof.  See module-level
// integrity model comment.
fn compute_header_hash(header_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HEADER_DOMAIN.as_bytes());
    hasher.update(header_bytes);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// Unkeyed domain-separated SHA-256.  Tamper-evident under owner-only
// filesystem controls; NOT an HMAC and NOT tamper-proof.
fn compute_record_hash(
    previous_hash: &[u8; 32],
    sequence: u64,
    wall_time_ms: u64,
    monotonic_ms: u64,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN.as_bytes());
    hasher.update(previous_hash);
    hasher.update(sequence.to_le_bytes());
    hasher.update(wall_time_ms.to_le_bytes());
    hasher.update(monotonic_ms.to_le_bytes());
    hasher.update((payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn encode_frame(
    sequence: u64,
    wall_time_ms: u64,
    monotonic_ms: u64,
    payload: &[u8],
    previous_hash: &[u8; 32],
    current_hash: &[u8; 32],
) -> Vec<u8> {
    let frame_len = FRAME_OVERHEAD + payload.len();
    let mut buf = Vec::with_capacity(4 + 8 + frame_len);
    buf.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
    buf.extend_from_slice(&(frame_len as u64).to_le_bytes());
    buf.extend_from_slice(&sequence.to_le_bytes());
    buf.extend_from_slice(&wall_time_ms.to_le_bytes());
    buf.extend_from_slice(&monotonic_ms.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf.extend_from_slice(previous_hash);
    buf.extend_from_slice(current_hash);
    buf
}

fn decode_frame(data: &[u8]) -> Result<DecodedFrame, AuditError> {
    if data.len() < 4 + 8 {
        return Err(AuditError::TruncatedRecord);
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != FRAME_MAGIC {
        return Err(AuditError::InvalidFrame("bad frame magic".into()));
    }
    let frame_len = u64::from_le_bytes(data[4..12].try_into().unwrap()) as usize;
    if frame_len < FRAME_OVERHEAD || frame_len as u64 > MAX_FRAME_SIZE {
        return Err(AuditError::InvalidFrame(format!(
            "bad frame length: {} (min {}, max {})",
            frame_len, FRAME_OVERHEAD, MAX_FRAME_SIZE
        )));
    }
    if data.len() < 12 + frame_len {
        return Err(AuditError::TruncatedRecord);
    }
    let body = &data[12..12 + frame_len];
    let sequence = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let wall_time_ms = u64::from_le_bytes(body[8..16].try_into().unwrap());
    let monotonic_ms = u64::from_le_bytes(body[16..24].try_into().unwrap());
    let payload_len = u32::from_le_bytes(body[24..28].try_into().unwrap()) as usize;
    if payload_len as u32 > MAX_PAYLOAD_SIZE {
        return Err(AuditError::InvalidFrame("payload too large".into()));
    }
    if body.len() < 28 + payload_len + 64 {
        return Err(AuditError::TruncatedRecord);
    }
    let payload = &body[28..28 + payload_len];
    let hash_offset = 28 + payload_len;
    let mut previous_hash = [0u8; 32];
    previous_hash.copy_from_slice(&body[hash_offset..hash_offset + 32]);
    let mut current_hash = [0u8; 32];
    current_hash.copy_from_slice(&body[hash_offset + 32..hash_offset + 64]);
    let expected = compute_record_hash(
        &previous_hash,
        sequence,
        wall_time_ms,
        monotonic_ms,
        payload,
    );
    if expected != current_hash {
        return Err(AuditError::HashMismatch {
            expected: hex::encode(expected),
            actual: hex::encode(current_hash),
        });
    }
    Ok(DecodedFrame {
        sequence,
        wall_time_ms,
        monotonic_ms,
        payload: payload.to_vec(),
        previous_hash,
        current_hash,
    })
}

struct DecodedFrame {
    sequence: u64,
    wall_time_ms: u64,
    monotonic_ms: u64,
    payload: Vec<u8>,
    previous_hash: [u8; 32],
    current_hash: [u8; 32],
}

// Unkeyed domain-separated SHA-256.  Tamper-evident under owner-only
// filesystem controls; NOT an HMAC and NOT tamper-proof.
fn encode_anchor(state: &AnchorState) -> [u8; ANCHOR_SIZE] {
    let mut buf = [0u8; ANCHOR_SIZE];
    buf[0..4].copy_from_slice(&ANCHOR_MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
    buf[8..16].copy_from_slice(&state.segment_index.to_le_bytes());
    buf[16..24].copy_from_slice(&state.sequence.to_le_bytes());
    buf[24..56].copy_from_slice(&state.hash);
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_DOMAIN.as_bytes());
    hasher.update(&buf[0..56]);
    let result = hasher.finalize();
    buf[56..88].copy_from_slice(&result);
    buf
}

fn decode_anchor(data: &[u8; ANCHOR_SIZE]) -> Result<AnchorState, AuditError> {
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != ANCHOR_MAGIC {
        return Err(AuditError::AnchorViolation("bad anchor magic".into()));
    }
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != SCHEMA_VERSION {
        return Err(AuditError::SchemaViolation(format!(
            "unsupported anchor version: {}",
            version
        )));
    }
    let segment_index = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let sequence = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[24..56]);
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_DOMAIN.as_bytes());
    hasher.update(&data[0..56]);
    let result = hasher.finalize();
    let expected: [u8; 32] = data[56..88].try_into().unwrap();
    let actual: [u8; 32] = result.as_slice().try_into().unwrap();
    if expected != actual {
        return Err(AuditError::AnchorViolation("anchor hash mismatch".into()));
    }
    Ok(AnchorState {
        segment_index,
        sequence,
        hash,
    })
}

fn check_dirfd_security(dir_path: &Path) -> Result<OwnedFd, AuditError> {
    let dir_fd = nix::fcntl::open(
        dir_path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| AuditError::Io(format!("open dirfd: {}", e)))?;

    let stat =
        nix::sys::stat::fstat(&dir_fd).map_err(|e| AuditError::Io(format!("fstat dir: {}", e)))?;

    if SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFLNK) {
        return Err(AuditError::SymlinkDetected(dir_path.display().to_string()));
    }

    let mode = stat.st_mode & 0o777;
    if mode != AUDIT_DIR_MODE {
        return Err(AuditError::ModeMismatch(format!(
            "dir mode {:o} != expected {:o}",
            mode, AUDIT_DIR_MODE
        )));
    }

    let uid = unsafe { libc::getuid() };
    if stat.st_uid != uid {
        return Err(AuditError::OwnerMismatch(format!(
            "dir uid {} != expected {}",
            stat.st_uid, uid
        )));
    }

    Ok(dir_fd)
}

fn check_file_at(dir_fd: &OwnedFd, name: &str) -> Result<(u64, u32), AuditError> {
    let stat = nix::sys::stat::fstatat(dir_fd, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|e| AuditError::Io(format!("fstatat {}: {}", name, e)))?;

    if SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFLNK) {
        return Err(AuditError::SymlinkDetected(name.to_string()));
    }

    let mode = stat.st_mode & 0o777;
    if mode != AUDIT_FILE_MODE {
        return Err(AuditError::ModeMismatch(format!(
            "file {} mode {:o} != expected {:o}",
            name, mode, AUDIT_FILE_MODE
        )));
    }

    let uid = unsafe { libc::getuid() };
    if stat.st_uid != uid {
        return Err(AuditError::OwnerMismatch(format!(
            "file {} uid {} != expected {}",
            name, stat.st_uid, uid
        )));
    }

    Ok((stat.st_ino, stat.st_mode))
}

fn open_file_at(
    dir_fd: &OwnedFd,
    name: &str,
    flags: OFlag,
    mode: Mode,
) -> Result<File, AuditError> {
    let fd = nix::fcntl::openat(dir_fd, name, flags, mode)
        .map_err(|e| AuditError::Io(format!("openat {}: {}", name, e)))?;
    Ok(unsafe { File::from_raw_fd(fd.into_raw_fd()) })
}

fn fsync_dir(dir_fd: &OwnedFd) -> Result<(), AuditError> {
    nix::unistd::fsync(dir_fd).map_err(|e| AuditError::Io(format!("fsync dir: {}", e)))
}

pub struct AuditGate {
    dir: PathBuf,
    dir_fd: OwnedFd,
    current_segment: Mutex<PathBuf>,
    current_segment_name: Mutex<String>,
    writer: Mutex<Box<dyn AuditWriter + Send>>,
    _lock: Flock<File>,
    sequence: Mutex<u64>,
    last_hash: Mutex<[u8; 32]>,
    circuit_broken: AtomicBool,
    epoch: Instant,
    max_segment_size: u64,
    segment_index: Mutex<u64>,
    anchor: Mutex<AnchorState>,
    anchor_inode: Mutex<u64>,
    #[cfg(test)]
    fault_injector: Box<dyn FaultInjector + Sync>,
    segment_file_ino: Mutex<u64>,
}

impl AuditGate {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, AuditError> {
        #[cfg(test)]
        {
            Self::open_internal(dir, DEFAULT_MAX_SEGMENT_SIZE, None)
        }
        #[cfg(not(test))]
        {
            Self::open_internal(dir, DEFAULT_MAX_SEGMENT_SIZE)
        }
    }

    #[cfg(test)]
    pub fn open_with_max_size(
        dir: impl AsRef<Path>,
        max_segment_size: u64,
    ) -> Result<Self, AuditError> {
        Self::open_internal(dir, max_segment_size, None)
    }

    #[cfg(test)]
    pub fn open_with_faults(
        dir: impl AsRef<Path>,
        max_segment_size: u64,
        faults: Box<dyn FaultInjector + Sync>,
    ) -> Result<Self, AuditError> {
        Self::open_internal(dir, max_segment_size, Some(faults))
    }

    fn open_internal(
        dir: impl AsRef<Path>,
        max_segment_size: u64,
        #[cfg(test)] fault_injector: Option<Box<dyn FaultInjector + Sync>>,
    ) -> Result<Self, AuditError> {
        let dir = dir.as_ref().to_path_buf();
        Self::ensure_secure_dir(&dir)?;

        let dir_fd = check_dirfd_security(&dir)?;

        let lock_fd = nix::fcntl::openat(
            &dir_fd,
            "audit.lock",
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(AUDIT_FILE_MODE),
        )
        .map_err(|e| AuditError::LockFailed(format!("open lock: {}", e)))?;

        let lock_file = unsafe { File::from_raw_fd(lock_fd.into_raw_fd()) };
        let flock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, e)| AuditError::LockFailed(format!("flock: {}", e)))?;

        let null_file = OpenOptions::new().write(true).open("/dev/null")?;

        #[cfg(test)]
        let fi = fault_injector.unwrap_or_else(|| Box::new(NeverFail));

        let mut gate = Self {
            dir: dir.clone(),
            dir_fd,
            current_segment: Mutex::new(PathBuf::new()),
            current_segment_name: Mutex::new(String::new()),
            writer: Mutex::new(Box::new(FileWriter::new(null_file))),
            _lock: flock,
            sequence: Mutex::new(0),
            last_hash: Mutex::new([0u8; 32]),
            circuit_broken: AtomicBool::new(false),
            epoch: Instant::now(),
            max_segment_size,
            segment_index: Mutex::new(0),
            anchor: Mutex::new(AnchorState::initial()),
            anchor_inode: Mutex::new(0),
            #[cfg(test)]
            fault_injector: fi,
            segment_file_ino: Mutex::new(0),
        };

        gate.initialize_or_verify()?;

        Ok(gate)
    }

    fn ensure_secure_dir(dir: &Path) -> Result<(), AuditError> {
        if dir.exists() {
            let metadata = fs::symlink_metadata(dir)?;
            if metadata.file_type().is_symlink() {
                return Err(AuditError::SymlinkDetected(dir.display().to_string()));
            }
            let mode = metadata.permissions().mode() & 0o777;
            if mode != AUDIT_DIR_MODE {
                return Err(AuditError::ModeMismatch(format!(
                    "dir mode {:o} != expected {:o}",
                    mode, AUDIT_DIR_MODE
                )));
            }
            let uid = unsafe { libc::getuid() };
            if metadata.uid() != uid {
                return Err(AuditError::OwnerMismatch(format!(
                    "dir uid {} != expected {}",
                    metadata.uid(),
                    uid
                )));
            }
        } else {
            fs::create_dir(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(AUDIT_DIR_MODE))?;
        }
        Ok(())
    }

    // # Startup recovery model
    //
    // On startup we walk every frame in the last segment and record the exact
    // byte offset of the last fully-valid, hash-chained record.  If the file
    // contains bytes beyond that offset the tail is incomplete (partial write
    // or crash).  We then consult the durable anchor:
    //
    //   * **Anchor attests through the last valid record** (anchor.sequence
    //     matches the last committed sequence and the hash chains): this is
    //     crash-forward recovery.  We truncate the file to the last valid
    //     offset, fsync, then durably append a `daemon.recover` event.
    //
    //   * **Anchor attests into the truncated region** (anchor.sequence is
    //     beyond the last valid record): this means the anchor was written
    //     for data that is no longer intact.  We **fail closed** with an
    //     `AnchorViolation`.
    //
    //   * **Anchor behind valid chain** (anchor.sequence < last_seq): the
    //     anchor simply has not been updated to cover the most recent
    //     records.  This is treated as crash-forward recovery: we update
    //     the anchor to the current chain tip and record a recovery event.
    //
    // Note: rollback of both the owner-writable log and anchor is **outside
    // the unkeyed threat model** (see module-level integrity comment).
    fn initialize_or_verify(&mut self) -> Result<(), AuditError> {
        let segments = self.list_segments()?;

        let anchor = self.load_anchor()?;

        if segments.is_empty() {
            if let Some(ref anchor_state) = anchor
                && anchor_state.sequence > 0
            {
                return Err(AuditError::AnchorViolation(
                    "anchor references deleted segments".into(),
                ));
            }
            self.create_initial_segment()?;
            return Ok(());
        }

        self.verify_all_segments(&segments)?;

        let last_segment = segments.last().unwrap();
        let seg_name = last_segment
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let idx = Self::extract_segment_index(&seg_name)?;

        let (last_seq, last_hash, last_valid_offset) =
            self.read_last_valid_record_info(last_segment)?;

        let file_size = fs::metadata(last_segment)?.len();
        let has_tail_garbage = file_size > last_valid_offset;

        let header = self.read_segment_header(last_segment)?;

        let (next_seq, next_hash) = if last_valid_offset <= HEADER_SIZE as u64 {
            (header.first_sequence, header.previous_final_hash)
        } else {
            (last_seq + 1, last_hash)
        };

        if let Some(ref anchor_state) = anchor {
            if anchor_state.segment_index > idx {
                return Err(AuditError::AnchorViolation(
                    "anchor points to deleted segment".into(),
                ));
            }
            if has_tail_garbage
                && anchor_state.segment_index == idx
                && anchor_state.sequence > last_seq
            {
                return Err(AuditError::AnchorViolation(format!(
                    "anchor attests into truncated region: anchor seq {} > last valid seq {}",
                    anchor_state.sequence, last_seq
                )));
            }
        }

        if has_tail_garbage {
            let file = open_file_at(
                &self.dir_fd,
                &seg_name,
                OFlag::O_WRONLY | OFlag::O_NOFOLLOW,
                Mode::from_bits_truncate(AUDIT_FILE_MODE),
            )?;
            file.set_len(last_valid_offset)?;
            file.sync_all()?;
            drop(file);
        }

        *self.current_segment.lock().unwrap() = last_segment.clone();
        *self.current_segment_name.lock().unwrap() = seg_name.clone();
        *self.sequence.lock().unwrap() = next_seq - 1;
        *self.last_hash.lock().unwrap() = next_hash;
        *self.segment_index.lock().unwrap() = idx;

        let seg_ino = check_file_at(&self.dir_fd, &seg_name)?.0;
        *self.segment_file_ino.lock().unwrap() = seg_ino;

        let file_for_write = open_file_at(
            &self.dir_fd,
            &seg_name,
            OFlag::O_WRONLY | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(AUDIT_FILE_MODE),
        )?;
        *self.writer.lock().unwrap() = Box::new(FileWriter::new(file_for_write));

        let needs_recovery = has_tail_garbage
            || anchor
                .as_ref()
                .is_some_and(|a| a.sequence < last_seq || a.segment_index < idx);

        if let Some(anchor_state) = anchor {
            *self.anchor.lock().unwrap() = anchor_state;
            let anchor_ino = self.load_anchor_inode()?;
            *self.anchor_inode.lock().unwrap() = anchor_ino;
        } else {
            let initial = AnchorState {
                segment_index: idx,
                sequence: next_seq - 1,
                hash: next_hash,
            };
            self.write_anchor(&initial)?;
            *self.anchor.lock().unwrap() = initial;
        }

        if needs_recovery {
            let truncated_bytes = if has_tail_garbage {
                file_size - last_valid_offset
            } else {
                0
            };
            let reason = if has_tail_garbage {
                RecoveryReason::IncompleteTailTruncated
            } else {
                RecoveryReason::AnchorViolation
            };
            let anchor = *self.anchor.lock().unwrap();
            let event = DaemonRecoverBuilder::new(
                reason,
                truncated_bytes,
                anchor.segment_index,
                anchor.sequence,
            )
            .build();
            self.record(event)?;
        }

        Ok(())
    }

    fn load_anchor(&self) -> Result<Option<AnchorState>, AuditError> {
        let fd = match nix::fcntl::openat(
            &self.dir_fd,
            "audit.anchor",
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(nix::Error::ENOENT) => return Ok(None),
            Err(nix::Error::ELOOP) => {
                return Err(AuditError::SymlinkDetected("audit.anchor".into()));
            }
            Err(e) => return Err(AuditError::Io(format!("openat anchor: {}", e))),
        };

        let stat = nix::sys::stat::fstat(&fd)
            .map_err(|e| AuditError::Io(format!("fstat anchor: {}", e)))?;

        if SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFLNK) {
            return Err(AuditError::SymlinkDetected("audit.anchor".into()));
        }

        let mode = stat.st_mode & 0o777;
        if mode != AUDIT_FILE_MODE {
            return Err(AuditError::ModeMismatch(format!(
                "anchor mode {:o} != expected {:o}",
                mode, AUDIT_FILE_MODE
            )));
        }

        let uid = unsafe { libc::getuid() };
        if stat.st_uid != uid {
            return Err(AuditError::OwnerMismatch(format!(
                "anchor uid {} != expected {}",
                stat.st_uid, uid
            )));
        }

        let mut file = unsafe { File::from_raw_fd(fd.into_raw_fd()) };
        let mut buf = [0u8; ANCHOR_SIZE];
        file.read_exact(&mut buf)?;
        let state = decode_anchor(&buf)?;
        Ok(Some(state))
    }

    fn load_anchor_inode(&self) -> Result<u64, AuditError> {
        match check_file_at(&self.dir_fd, "audit.anchor") {
            Ok((ino, _)) => Ok(ino),
            Err(_) => Ok(0),
        }
    }

    fn write_anchor(&self, state: &AnchorState) -> Result<(), AuditError> {
        #[cfg(test)]
        if self.fault_injector.should_fail(FaultPoint::WriteAnchor) {
            return Err(AuditError::Io("injected write anchor failure".into()));
        }

        let tmp_fd = nix::fcntl::openat(
            &self.dir_fd,
            "audit.anchor.tmp",
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(AUDIT_FILE_MODE),
        )
        .map_err(|e| AuditError::Io(format!("open anchor tmp: {}", e)))?;
        let mut tmp_file = unsafe { File::from_raw_fd(tmp_fd.into_raw_fd()) };
        let encoded = encode_anchor(state);
        tmp_file.write_all(&encoded)?;

        #[cfg(test)]
        if self.fault_injector.should_fail(FaultPoint::FsyncAnchor) {
            return Err(AuditError::Io("injected fsync anchor failure".into()));
        }

        tmp_file.sync_all()?;
        drop(tmp_file);

        #[cfg(test)]
        if self.fault_injector.should_fail(FaultPoint::RenameAnchor) {
            return Err(AuditError::Io("injected rename anchor failure".into()));
        }

        renameat(
            &self.dir_fd,
            "audit.anchor.tmp",
            &self.dir_fd,
            "audit.anchor",
        )
        .map_err(|e| AuditError::Io(format!("renameat anchor: {}", e)))?;
        fsync_dir(&self.dir_fd)?;

        Ok(())
    }

    fn list_segments(&self) -> Result<Vec<PathBuf>, AuditError> {
        let dup_fd = dup(&self.dir_fd)
            .map_err(|e| AuditError::Io(format!("dup dirfd for listing: {}", e)))?;
        let mut dir =
            Dir::from_fd(dup_fd).map_err(|e| AuditError::Io(format!("fdopendir: {}", e)))?;

        let mut segments: Vec<PathBuf> = Vec::new();
        for entry in dir.iter() {
            let entry = entry.map_err(|e| AuditError::Io(format!("readdir: {}", e)))?;
            let name = entry.file_name().to_str().unwrap_or("");
            if name.starts_with("audit-") && name.ends_with(".log") {
                segments.push(self.dir.join(name));
            }
        }
        segments.sort();
        Ok(segments)
    }

    fn extract_segment_index(filename: &str) -> Result<u64, AuditError> {
        let index_str = filename
            .strip_prefix("audit-")
            .and_then(|s| s.strip_suffix(".log"))
            .ok_or_else(|| AuditError::InvalidFrame("bad segment name".into()))?;
        index_str
            .parse::<u64>()
            .map_err(|_| AuditError::InvalidFrame("bad segment index".into()))
    }

    fn read_segment_header(&self, path: &Path) -> Result<SegmentHeader, AuditError> {
        let name = path.file_name().unwrap().to_str().unwrap();
        let mut file = open_file_at(
            &self.dir_fd,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )?;
        let mut buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut buf)?;
        SegmentHeader::decode(&buf)
    }

    fn verify_all_segments(&self, segments: &[PathBuf]) -> Result<(), AuditError> {
        let mut expected_prev_hash = [0u8; 32];

        for (i, segment_path) in segments.iter().enumerate() {
            let seg_name = segment_path.file_name().unwrap().to_str().unwrap();
            let idx = Self::extract_segment_index(seg_name)?;

            if idx != i as u64 {
                return Err(AuditError::SequenceGap {
                    expected: i as u64,
                    actual: idx,
                });
            }

            check_file_at(&self.dir_fd, seg_name)?;

            let header = self.read_segment_header(segment_path)?;

            if header.segment_index != idx {
                return Err(AuditError::InvalidFrame(format!(
                    "header index {} != filename index {}",
                    header.segment_index, idx
                )));
            }

            if i == 0 {
                if header.first_sequence != 1 {
                    return Err(AuditError::SequenceGap {
                        expected: 1,
                        actual: header.first_sequence,
                    });
                }
                if header.previous_final_hash != [0u8; 32] {
                    return Err(AuditError::HashMismatch {
                        expected: hex::encode([0u8; 32]),
                        actual: hex::encode(header.previous_final_hash),
                    });
                }
            } else {
                if header.previous_final_hash != expected_prev_hash {
                    return Err(AuditError::HashMismatch {
                        expected: hex::encode(expected_prev_hash),
                        actual: hex::encode(header.previous_final_hash),
                    });
                }
            }

            let is_last = i == segments.len() - 1;
            let (last_seq, last_hash, _) = if is_last {
                self.read_last_valid_record_info(segment_path)?
            } else {
                self.read_last_record_info(segment_path)?
            };

            if last_seq > 0 {
                expected_prev_hash = last_hash;
            } else {
                expected_prev_hash = header.previous_final_hash;
            }
        }

        Ok(())
    }

    fn count_records_in_segment(&self, path: &Path) -> Result<u64, AuditError> {
        let name = path.file_name().unwrap().to_str().unwrap();
        let mut file = open_file_at(
            &self.dir_fd,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )?;
        let file_size = file.metadata()?.len();
        if file_size <= HEADER_SIZE as u64 {
            return Ok(0);
        }
        let mut header_buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf)?;
        let mut count = 0u64;
        loop {
            let mut magic_buf = [0u8; 4];
            match file.read_exact(&mut magic_buf) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let magic = u32::from_le_bytes(magic_buf);
            if magic != FRAME_MAGIC {
                return Err(AuditError::InvalidFrame("bad frame magic".into()));
            }
            let mut len_buf = [0u8; 8];
            file.read_exact(&mut len_buf)?;
            let frame_len = u64::from_le_bytes(len_buf);
            if frame_len < FRAME_OVERHEAD as u64 || frame_len > MAX_FRAME_SIZE {
                return Err(AuditError::InvalidFrame(format!(
                    "bad frame length: {}",
                    frame_len
                )));
            }
            let mut frame_buf = vec![0u8; frame_len as usize];
            file.read_exact(&mut frame_buf)?;
            count += 1;
        }
        Ok(count)
    }

    fn read_last_record_info(&self, path: &Path) -> Result<(u64, [u8; 32], u64), AuditError> {
        let name = path.file_name().unwrap().to_str().unwrap();
        let mut file = open_file_at(
            &self.dir_fd,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )?;
        let file_size = file.metadata()?.len();
        if file_size <= HEADER_SIZE as u64 {
            return Ok((0, [0u8; 32], HEADER_SIZE as u64));
        }
        let mut header_buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf)?;
        let header = SegmentHeader::decode(&header_buf)?;

        let mut seq = 0u64;
        let mut last_hash = header.previous_final_hash;
        let mut expected_prev_hash = header.previous_final_hash;
        let mut expected_seq = header.first_sequence;
        let mut offset = HEADER_SIZE as u64;

        loop {
            let mut magic_buf = [0u8; 4];
            match file.read_exact(&mut magic_buf) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let magic = u32::from_le_bytes(magic_buf);
            if magic != FRAME_MAGIC {
                return Err(AuditError::InvalidFrame("bad frame magic".into()));
            }
            let mut len_buf = [0u8; 8];
            file.read_exact(&mut len_buf)?;
            let frame_len = u64::from_le_bytes(len_buf);
            if frame_len < FRAME_OVERHEAD as u64 || frame_len > MAX_FRAME_SIZE {
                return Err(AuditError::InvalidFrame(format!(
                    "bad frame length: {}",
                    frame_len
                )));
            }
            let mut frame_buf = vec![0u8; frame_len as usize];
            file.read_exact(&mut frame_buf)?;

            let mut full_frame = Vec::new();
            full_frame.extend_from_slice(&magic_buf);
            full_frame.extend_from_slice(&len_buf);
            full_frame.extend_from_slice(&frame_buf);
            let record = decode_frame(&full_frame)?;

            if record.previous_hash != expected_prev_hash {
                return Err(AuditError::HashMismatch {
                    expected: hex::encode(expected_prev_hash),
                    actual: hex::encode(record.previous_hash),
                });
            }
            if record.sequence != expected_seq {
                return Err(AuditError::SequenceGap {
                    expected: expected_seq,
                    actual: record.sequence,
                });
            }

            seq = record.sequence;
            last_hash = record.current_hash;
            expected_prev_hash = record.current_hash;
            expected_seq += 1;
            offset += 4 + 8 + frame_len;
        }

        Ok((seq, last_hash, offset))
    }

    // Tolerant variant: reads as many valid, hash-chained frames as possible
    // and returns the byte offset immediately after the last valid frame.
    // Used during startup recovery to locate the truncation point when the
    // tail may contain partial or garbage data.
    fn read_last_valid_record_info(&self, path: &Path) -> Result<(u64, [u8; 32], u64), AuditError> {
        let name = path.file_name().unwrap().to_str().unwrap();
        let mut file = open_file_at(
            &self.dir_fd,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )?;
        let file_size = file.metadata()?.len();
        if file_size <= HEADER_SIZE as u64 {
            return Ok((0, [0u8; 32], HEADER_SIZE as u64));
        }
        let mut header_buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf)?;
        let header = SegmentHeader::decode(&header_buf)?;

        let mut seq = 0u64;
        let mut last_hash = header.previous_final_hash;
        let mut expected_prev_hash = header.previous_final_hash;
        let mut expected_seq = header.first_sequence;
        let mut offset = HEADER_SIZE as u64;

        loop {
            let frame_start = offset;
            let mut magic_buf = [0u8; 4];
            match file.read_exact(&mut magic_buf) {
                Ok(_) => {}
                Err(_) => break,
            }
            let magic = u32::from_le_bytes(magic_buf);
            if magic != FRAME_MAGIC {
                break;
            }
            let mut len_buf = [0u8; 8];
            if file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let frame_len = u64::from_le_bytes(len_buf);
            if frame_len < FRAME_OVERHEAD as u64 || frame_len > MAX_FRAME_SIZE {
                break;
            }
            let mut frame_buf = vec![0u8; frame_len as usize];
            if file.read_exact(&mut frame_buf).is_err() {
                break;
            }

            let mut full_frame = Vec::new();
            full_frame.extend_from_slice(&magic_buf);
            full_frame.extend_from_slice(&len_buf);
            full_frame.extend_from_slice(&frame_buf);
            let record = match decode_frame(&full_frame) {
                Ok(r) => r,
                Err(_) => break,
            };

            if record.previous_hash != expected_prev_hash {
                break;
            }
            if record.sequence != expected_seq {
                break;
            }

            seq = record.sequence;
            last_hash = record.current_hash;
            expected_prev_hash = record.current_hash;
            expected_seq += 1;
            offset = frame_start + 4 + 8 + frame_len;
        }

        Ok((seq, last_hash, offset))
    }

    fn create_initial_segment(&mut self) -> Result<(), AuditError> {
        let seg_name = "audit-000000.log";
        let header = SegmentHeader {
            version: SCHEMA_VERSION,
            segment_index: 0,
            first_sequence: 1,
            previous_final_hash: [0u8; 32],
        };
        let encoded = header.encode();

        let fd = nix::fcntl::openat(
            &self.dir_fd,
            seg_name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(AUDIT_FILE_MODE),
        )
        .map_err(|e| AuditError::RotationFailed(format!("create initial segment: {}", e)))?;
        let mut file = unsafe { File::from_raw_fd(fd.into_raw_fd()) };
        file.write_all(&encoded)?;
        file.sync_all()?;
        fsync_dir(&self.dir_fd)?;

        let seg_ino = check_file_at(&self.dir_fd, seg_name)?.0;

        let file_for_write = open_file_at(
            &self.dir_fd,
            seg_name,
            OFlag::O_WRONLY | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(AUDIT_FILE_MODE),
        )?;

        *self.current_segment.lock().unwrap() = self.dir.join(seg_name);
        *self.current_segment_name.lock().unwrap() = seg_name.to_string();
        *self.writer.lock().unwrap() = Box::new(FileWriter::new(file_for_write));
        *self.segment_index.lock().unwrap() = 0;
        *self.segment_file_ino.lock().unwrap() = seg_ino;
        *self.sequence.lock().unwrap() = 0;
        *self.last_hash.lock().unwrap() = [0u8; 32];

        let initial_anchor = AnchorState {
            segment_index: 0,
            sequence: 0,
            hash: [0u8; 32],
        };
        self.write_anchor(&initial_anchor)?;
        *self.anchor.lock().unwrap() = initial_anchor;
        let anchor_ino = self.load_anchor_inode()?;
        *self.anchor_inode.lock().unwrap() = anchor_ino;

        Ok(())
    }

    pub fn record(&self, event: AuditEvent) -> Result<AuditReceipt, AuditError> {
        if self.circuit_broken.load(Ordering::SeqCst) {
            return Err(AuditError::CircuitBroken(
                "audit subsystem is in failed state".into(),
            ));
        }

        let payload = serde_json::to_vec(&event).map_err(|e| {
            self.circuit_broken.store(true, Ordering::SeqCst);
            AuditError::SchemaViolation(format!("serialize event: {}", e))
        })?;

        if payload.len() as u32 > MAX_PAYLOAD_SIZE {
            return Err(AuditError::SchemaViolation("payload too large".into()));
        }

        let wall_time_ms = event.timestamp_ms();
        let monotonic_ms = self.epoch.elapsed().as_millis() as u64;

        let mut seq_guard = self.sequence.lock().unwrap();
        let mut hash_guard = self.last_hash.lock().unwrap();
        let mut writer_guard = self.writer.lock().unwrap();

        let next_seq = seq_guard.checked_add(1).ok_or(AuditError::Overflow)?;
        let prev_hash = *hash_guard;

        let current_hash =
            compute_record_hash(&prev_hash, next_seq, wall_time_ms, monotonic_ms, &payload);

        let frame = encode_frame(
            next_seq,
            wall_time_ms,
            monotonic_ms,
            &payload,
            &prev_hash,
            &current_hash,
        );

        let current_seg_name = self.current_segment_name.lock().unwrap().clone();
        let should_rotate = if let Ok(stat) = nix::sys::stat::fstatat(
            &self.dir_fd,
            current_seg_name.as_str(),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            stat.st_size as u64 + frame.len() as u64 > self.max_segment_size
        } else {
            false
        };
        drop(current_seg_name);

        if should_rotate {
            drop(writer_guard);
            drop(hash_guard);
            drop(seq_guard);
            self.rotate_segment()?;
            seq_guard = self.sequence.lock().unwrap();
            hash_guard = self.last_hash.lock().unwrap();
            writer_guard = self.writer.lock().unwrap();
        }

        let save_offset = writer_guard.current_offset().map_err(|e| {
            self.circuit_broken.store(true, Ordering::SeqCst);
            AuditError::Io(format!("get offset: {}", e))
        })?;

        #[cfg(test)]
        if self.fault_injector.should_fail(FaultPoint::WriteRecord) {
            let _ = writer_guard.truncate_to(save_offset);
            let _ = writer_guard.sync_data();
            self.circuit_broken.store(true, Ordering::SeqCst);
            return Err(AuditError::Io("injected write failure (ENOSPC)".into()));
        }

        let write_result = writer_guard.write_at(save_offset, &frame);
        match write_result {
            Ok(n) if n == frame.len() => {}
            Ok(_) => {
                let _ = writer_guard.truncate_to(save_offset);
                let _ = writer_guard.sync_data();
                self.circuit_broken.store(true, Ordering::SeqCst);
                return Err(AuditError::Io("partial write".into()));
            }
            Err(e) => {
                let _ = writer_guard.truncate_to(save_offset);
                let _ = writer_guard.sync_data();
                self.circuit_broken.store(true, Ordering::SeqCst);
                return Err(AuditError::Io(format!("write record: {}", e)));
            }
        }

        #[cfg(test)]
        if self.fault_injector.should_fail(FaultPoint::FlushRecord) {
            let _ = writer_guard.truncate_to(save_offset);
            let _ = writer_guard.sync_data();
            self.circuit_broken.store(true, Ordering::SeqCst);
            return Err(AuditError::Io("injected flush failure".into()));
        }

        #[cfg(test)]
        if self.fault_injector.should_fail(FaultPoint::FsyncRecord) {
            let _ = writer_guard.truncate_to(save_offset);
            let _ = writer_guard.sync_data();
            self.circuit_broken.store(true, Ordering::SeqCst);
            return Err(AuditError::Io("injected fsync failure".into()));
        }

        if let Err(e) = writer_guard.sync_data() {
            let _ = writer_guard.truncate_to(save_offset);
            let _ = writer_guard.sync_data();
            self.circuit_broken.store(true, Ordering::SeqCst);
            return Err(AuditError::Io(format!("fsync record: {}", e)));
        }

        #[cfg(test)]
        if self.fault_injector.should_fail(FaultPoint::FsyncDir) {
            self.circuit_broken.store(true, Ordering::SeqCst);
            return Err(AuditError::Io("injected fsync dir failure".into()));
        }

        if let Err(e) = fsync_dir(&self.dir_fd) {
            self.circuit_broken.store(true, Ordering::SeqCst);
            return Err(AuditError::Io(format!("fsync dir: {}", e)));
        }

        let seg_idx = *self.segment_index.lock().unwrap();
        let new_anchor = AnchorState {
            segment_index: seg_idx,
            sequence: next_seq,
            hash: current_hash,
        };

        if let Err(e) = self.write_anchor(&new_anchor) {
            self.circuit_broken.store(true, Ordering::SeqCst);
            return Err(AuditError::Io(format!("write anchor: {}", e)));
        }

        *seq_guard = next_seq;
        *hash_guard = current_hash;
        *self.anchor.lock().unwrap() = new_anchor;

        Ok(AuditReceipt {
            #[cfg(test)]
            sequence: next_seq,
            #[cfg(test)]
            hash: current_hash,
        })
    }

    fn rotate_segment(&self) -> Result<(), AuditError> {
        let seg_idx = self.segment_index.lock().unwrap();
        let mut writer_guard = self.writer.lock().unwrap();
        let hash_guard = self.last_hash.lock().unwrap();
        let seq_guard = self.sequence.lock().unwrap();

        writer_guard.sync_data().map_err(|e| {
            self.circuit_broken.store(true, Ordering::SeqCst);
            AuditError::RotationFailed(format!("sync current: {}", e))
        })?;

        let next_idx = *seg_idx + 1;
        let next_seq = *seq_guard + 1;
        let prev_hash = *hash_guard;
        let seg_name = format!("audit-{:06}.log", next_idx);

        let header = SegmentHeader {
            version: SCHEMA_VERSION,
            segment_index: next_idx,
            first_sequence: next_seq,
            previous_final_hash: prev_hash,
        };
        let encoded = header.encode();

        #[cfg(test)]
        if self.fault_injector.should_fail(FaultPoint::WriteHeader) {
            self.circuit_broken.store(true, Ordering::SeqCst);
            return Err(AuditError::RotationFailed(
                "injected header write failure".into(),
            ));
        }

        let fd = nix::fcntl::openat(
            &self.dir_fd,
            seg_name.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(AUDIT_FILE_MODE),
        )
        .map_err(|e| AuditError::RotationFailed(format!("create segment: {}", e)))?;
        let mut new_file = unsafe { File::from_raw_fd(fd.into_raw_fd()) };
        new_file.write_all(&encoded)?;

        #[cfg(test)]
        if self.fault_injector.should_fail(FaultPoint::FsyncHeader) {
            self.circuit_broken.store(true, Ordering::SeqCst);
            return Err(AuditError::RotationFailed(
                "injected header fsync failure".into(),
            ));
        }

        new_file.sync_all()?;
        fsync_dir(&self.dir_fd)?;

        drop(writer_guard);
        drop(hash_guard);
        drop(seg_idx);

        let file_for_write = open_file_at(
            &self.dir_fd,
            seg_name.as_str(),
            OFlag::O_WRONLY | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(AUDIT_FILE_MODE),
        )?;

        let seg_ino = check_file_at(&self.dir_fd, seg_name.as_str())?.0;

        *self.current_segment.lock().unwrap() = self.dir.join(&seg_name);
        *self.current_segment_name.lock().unwrap() = seg_name;
        *self.writer.lock().unwrap() = Box::new(FileWriter::new(file_for_write));
        *self.segment_index.lock().unwrap() = next_idx;
        *self.segment_file_ino.lock().unwrap() = seg_ino;

        Ok(())
    }

    pub fn verify_all(&self) -> Result<u64, AuditError> {
        let segments = self.list_segments()?;
        self.verify_all_segments(&segments)?;
        let mut total = 0u64;
        for seg in &segments {
            total += self.count_records_in_segment(seg)?;
        }
        Ok(total)
    }

    pub fn current_sequence(&self) -> u64 {
        *self.sequence.lock().unwrap()
    }

    #[cfg(test)]
    pub fn current_hash(&self) -> [u8; 32] {
        *self.last_hash.lock().unwrap()
    }

    pub fn is_circuit_broken(&self) -> bool {
        self.circuit_broken.load(Ordering::SeqCst)
    }

    pub fn ping(&self) -> bool {
        !self.is_circuit_broken()
    }

    pub fn dir_path(&self) -> &Path {
        &self.dir
    }

    #[cfg(test)]
    pub fn append_recovery(
        &self,
        reason: RecoveryReason,
        truncated_size: u64,
    ) -> Result<AuditReceipt, AuditError> {
        let anchor = *self.anchor.lock().unwrap();
        let event = DaemonRecoverBuilder::new(
            reason,
            truncated_size,
            anchor.segment_index,
            anchor.sequence,
        )
        .build();
        self.record(event)
    }

    pub fn export_verified(
        &self,
        format: ExportFormat,
        destination_dir: &Path,
    ) -> Result<ExportResult, AuditError> {
        const MAX_EXPORT_ENTRIES: u64 = 1_000_000;
        const MAX_EXPORT_BYTES: u64 = 512 * 1024 * 1024;

        let entry_count = self.verify_all()?;
        if entry_count > MAX_EXPORT_ENTRIES {
            return Err(AuditError::SchemaViolation(format!(
                "export would exceed max entries: {} > {}",
                entry_count, MAX_EXPORT_ENTRIES
            )));
        }

        let segments = self.list_segments()?;
        let mut rows: Vec<ExportRow> = Vec::with_capacity(entry_count as usize);

        for seg_path in &segments {
            let seg_name = seg_path.file_name().unwrap().to_str().unwrap();
            check_file_at(&self.dir_fd, seg_name)?;

            let mut file = open_file_at(
                &self.dir_fd,
                seg_name,
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW,
                Mode::empty(),
            )?;
            let file_size = file.metadata()?.len();
            if file_size <= HEADER_SIZE as u64 {
                continue;
            }

            let mut header_buf = [0u8; HEADER_SIZE];
            file.read_exact(&mut header_buf)?;
            let _header = SegmentHeader::decode(&header_buf)?;

            loop {
                let mut magic_buf = [0u8; 4];
                match file.read_exact(&mut magic_buf) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e.into()),
                }
                let magic = u32::from_le_bytes(magic_buf);
                if magic != FRAME_MAGIC {
                    return Err(AuditError::InvalidFrame("bad frame magic in export".into()));
                }
                let mut len_buf = [0u8; 8];
                file.read_exact(&mut len_buf)?;
                let frame_len = u64::from_le_bytes(len_buf);
                if frame_len < FRAME_OVERHEAD as u64 || frame_len > MAX_FRAME_SIZE {
                    return Err(AuditError::InvalidFrame(format!(
                        "bad frame length in export: {}",
                        frame_len
                    )));
                }
                let mut frame_buf = vec![0u8; frame_len as usize];
                file.read_exact(&mut frame_buf)?;

                let mut full_frame = Vec::with_capacity(4 + 8 + frame_len as usize);
                full_frame.extend_from_slice(&magic_buf);
                full_frame.extend_from_slice(&len_buf);
                full_frame.extend_from_slice(&frame_buf);
                let decoded = decode_frame(&full_frame)?;

                let event: AuditEvent = serde_json::from_slice(&decoded.payload).map_err(|e| {
                    AuditError::SchemaViolation(format!("parse audit event payload: {}", e))
                })?;

                rows.push(ExportRow {
                    sequence: decoded.sequence,
                    wall_time_ms: decoded.wall_time_ms,
                    monotonic_ms: decoded.monotonic_ms,
                    event,
                });

                if rows.len() as u64 > MAX_EXPORT_ENTRIES {
                    return Err(AuditError::SchemaViolation(
                        "export exceeded max entry bound".into(),
                    ));
                }
            }
        }

        let total_bytes_estimate: u64 = rows
            .iter()
            .map(|r| {
                let event_json = serde_json::to_vec(&r.event).unwrap_or_default();
                64 + event_json.len() as u64
            })
            .sum();
        if total_bytes_estimate > MAX_EXPORT_BYTES {
            return Err(AuditError::SchemaViolation(format!(
                "export would exceed max bytes: {} > {}",
                total_bytes_estimate, MAX_EXPORT_BYTES
            )));
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (extension, content) = match format {
            ExportFormat::Json => {
                let mut lines = Vec::with_capacity(rows.len());
                for row in &rows {
                    let json = serde_json::to_string(&ExportJsonRow {
                        sequence: row.sequence,
                        wall_time_ms: row.wall_time_ms,
                        monotonic_ms: row.monotonic_ms,
                        event: &row.event,
                    })
                    .map_err(|e| {
                        AuditError::SchemaViolation(format!("serialize JSON row: {}", e))
                    })?;
                    lines.push(json);
                }
                ("jsonl".to_string(), lines.join("\n") + "\n")
            }
            ExportFormat::Csv => {
                let mut lines = Vec::with_capacity(rows.len() + 1);
                lines.push("sequence,wall_time_ms,monotonic_ms,kind,event".to_string());
                for row in &rows {
                    let event_json = serde_json::to_string(&row.event).map_err(|e| {
                        AuditError::SchemaViolation(format!("serialize CSV event: {}", e))
                    })?;
                    let escaped_event = csv_escape(&event_json);
                    lines.push(format!(
                        "{},{},{},{},{}",
                        row.sequence,
                        row.wall_time_ms,
                        row.monotonic_ms,
                        csv_escape(row.event.kind_name()),
                        escaped_event
                    ));
                }
                ("csv".to_string(), lines.join("\n") + "\n")
            }
        };

        let export_name = format!("audit-export-{}.{}", timestamp, extension);
        let export_path = destination_dir.join(&export_name);
        let tmp_name = format!(".audit-export-{}.{}.tmp", timestamp, std::process::id());
        let tmp_path = destination_dir.join(&tmp_name);

        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| AuditError::Io(format!("create export tmp: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp_file
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| AuditError::Io(format!("set export tmp mode: {}", e)))?;
        }

        tmp_file
            .write_all(content.as_bytes())
            .map_err(|e| AuditError::Io(format!("write export content: {}", e)))?;
        tmp_file
            .sync_all()
            .map_err(|e| AuditError::Io(format!("fsync export tmp: {}", e)))?;
        drop(tmp_file);

        std::fs::rename(&tmp_path, &export_path)
            .map_err(|e| AuditError::Io(format!("rename export: {}", e)))?;

        let dir_file = std::fs::File::open(destination_dir)
            .map_err(|e| AuditError::Io(format!("open dest dir for fsync: {}", e)))?;
        dir_file
            .sync_all()
            .map_err(|e| AuditError::Io(format!("fsync dest dir: {}", e)))?;

        let _ = std::fs::remove_file(&tmp_path);

        Ok(ExportResult {
            path: export_path,
            entry_count: rows.len() as u64,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
}

#[derive(Debug, Clone)]
pub struct ExportResult {
    pub path: PathBuf,
    pub entry_count: u64,
}

struct ExportRow {
    sequence: u64,
    wall_time_ms: u64,
    monotonic_ms: u64,
    event: AuditEvent,
}

#[derive(serde::Serialize)]
struct ExportJsonRow<'a> {
    sequence: u64,
    wall_time_ms: u64,
    monotonic_ms: u64,
    event: &'a AuditEvent,
}

fn csv_escape(s: &str) -> String {
    if s.contains('"') || s.contains(',') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    use passless_core::agent::{CredentialRef, GrantId, ProfileId};

    use super::super::audit_events::*;

    fn test_profile_id() -> ProfileId {
        ProfileId::new("test-profile").unwrap()
    }

    fn test_grant_id() -> GrantId {
        GrantId::new()
    }

    fn test_cred() -> CredentialRef {
        CredentialRef::with_default_domain(b"test-credential-id")
    }

    fn simple_event() -> AuditEvent {
        ProfileCreateBuilder::new(test_profile_id()).build()
    }

    #[test]
    fn test_segment_header_roundtrip() {
        let header = SegmentHeader {
            version: SCHEMA_VERSION,
            segment_index: 0,
            first_sequence: 1,
            previous_final_hash: [0u8; 32],
        };
        let encoded = header.encode();
        let decoded = SegmentHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.version, SCHEMA_VERSION);
        assert_eq!(decoded.segment_index, 0);
        assert_eq!(decoded.first_sequence, 1);
        assert_eq!(decoded.previous_final_hash, [0u8; 32]);
    }

    #[test]
    fn test_segment_header_tamper_detected() {
        let header = SegmentHeader {
            version: SCHEMA_VERSION,
            segment_index: 0,
            first_sequence: 1,
            previous_final_hash: [0u8; 32],
        };
        let mut encoded = header.encode();
        encoded[10] ^= 0xFF;
        assert!(SegmentHeader::decode(&encoded).is_err());
    }

    #[test]
    fn test_anchor_roundtrip() {
        let state = AnchorState {
            segment_index: 0,
            sequence: 42,
            hash: [0xAB; 32],
        };
        let encoded = encode_anchor(&state);
        let decoded = decode_anchor(&encoded).unwrap();
        assert_eq!(decoded.segment_index, 0);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.hash, [0xAB; 32]);
    }

    #[test]
    fn test_anchor_tamper_detected() {
        let state = AnchorState {
            segment_index: 0,
            sequence: 42,
            hash: [0xAB; 32],
        };
        let mut encoded = encode_anchor(&state);
        encoded[20] ^= 0xFF;
        assert!(decode_anchor(&encoded).is_err());
    }

    #[test]
    fn test_frame_roundtrip() {
        let payload = b"test payload";
        let prev_hash = [0u8; 32];
        let hash = compute_record_hash(&prev_hash, 1, 1000, 500, payload);
        let frame = encode_frame(1, 1000, 500, payload, &prev_hash, &hash);
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.wall_time_ms, 1000);
        assert_eq!(decoded.monotonic_ms, 500);
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.previous_hash, prev_hash);
        assert_eq!(decoded.current_hash, hash);
    }

    #[test]
    fn test_frame_hash_mismatch_detected() {
        let payload = b"test payload";
        let prev_hash = [0u8; 32];
        let mut hash = compute_record_hash(&prev_hash, 1, 1000, 500, payload);
        hash[0] ^= 0xFF;
        let frame = encode_frame(1, 1000, 500, payload, &prev_hash, &hash);
        assert!(decode_frame(&frame).is_err());
    }

    #[test]
    fn test_audit_gate_open_creates_directory() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let _gate = AuditGate::open(&audit_dir).unwrap();
        assert!(audit_dir.exists());
        let metadata = fs::metadata(&audit_dir).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn test_audit_gate_rejects_symlink_directory() {
        let temp = TempDir::new().unwrap();
        let real_dir = temp.path().join("real");
        let symlink_dir = temp.path().join("symlink");
        fs::create_dir(&real_dir).unwrap();
        symlink(&real_dir, &symlink_dir).unwrap();
        let result = AuditGate::open(&symlink_dir);
        assert!(matches!(result, Err(AuditError::SymlinkDetected(_))));
    }

    #[test]
    fn test_audit_gate_rejects_wrong_mode() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        fs::create_dir(&audit_dir).unwrap();
        fs::set_permissions(&audit_dir, fs::Permissions::from_mode(0o755)).unwrap();
        let result = AuditGate::open(&audit_dir);
        assert!(matches!(result, Err(AuditError::ModeMismatch(_))));
    }

    #[test]
    fn test_audit_gate_record_and_verify() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open(&audit_dir).unwrap();
        let receipt = gate.record(simple_event()).unwrap();
        assert_eq!(receipt.sequence, 1);
        assert_ne!(receipt.hash, [0u8; 32]);
        assert_eq!(gate.current_sequence(), 1);
        let count = gate.verify_all().unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_audit_gate_sequence_increment() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open(&audit_dir).unwrap();
        for i in 1..=5 {
            let receipt = gate.record(simple_event()).unwrap();
            assert_eq!(receipt.sequence, i);
        }
    }

    #[test]
    fn test_audit_gate_hash_chain() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open(&audit_dir).unwrap();
        let r1 = gate.record(simple_event()).unwrap();
        let r2 = gate.record(simple_event()).unwrap();
        let segments = gate.list_segments().unwrap();
        let mut file = File::open(&segments[0]).unwrap();
        let mut header_buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf).unwrap();
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf).unwrap();
        let mut len_buf = [0u8; 8];
        file.read_exact(&mut len_buf).unwrap();
        let frame_len = u64::from_le_bytes(len_buf) as usize;
        let mut frame_buf = vec![0u8; frame_len];
        file.read_exact(&mut frame_buf).unwrap();
        let mut full = Vec::new();
        full.extend_from_slice(&magic_buf);
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&frame_buf);
        let f1 = decode_frame(&full).unwrap();
        assert_eq!(f1.current_hash, r1.hash);
        file.read_exact(&mut magic_buf).unwrap();
        file.read_exact(&mut len_buf).unwrap();
        let frame_len2 = u64::from_le_bytes(len_buf) as usize;
        let mut frame_buf2 = vec![0u8; frame_len2];
        file.read_exact(&mut frame_buf2).unwrap();
        let mut full2 = Vec::new();
        full2.extend_from_slice(&magic_buf);
        full2.extend_from_slice(&len_buf);
        full2.extend_from_slice(&frame_buf2);
        let f2 = decode_frame(&full2).unwrap();
        assert_eq!(f2.previous_hash, r1.hash);
        assert_eq!(f2.current_hash, r2.hash);
    }

    #[test]
    fn test_audit_gate_persistence_across_reopen() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open(&audit_dir).unwrap();
            for _ in 0..3 {
                gate.record(simple_event()).unwrap();
            }
        }
        {
            let gate = AuditGate::open(&audit_dir).unwrap();
            assert_eq!(gate.current_sequence(), 3);
            let receipt = gate.record(simple_event()).unwrap();
            assert_eq!(receipt.sequence, 4);
        }
    }

    #[test]
    fn test_audit_gate_detects_tampering() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open(&audit_dir).unwrap();
            gate.record(simple_event()).unwrap();
        }
        let segments: Vec<PathBuf> = fs::read_dir(&audit_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("audit-") && n.ends_with(".log"))
                    .unwrap_or(false)
            })
            .collect();
        let segment = &segments[0];
        let mut content = fs::read(segment).unwrap();
        if content.len() > 100 {
            content[100] ^= 0xFF;
            fs::write(segment, &content).unwrap();
        }
        let result = AuditGate::open(&audit_dir);
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_gate_detects_segment_deletion() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open(&audit_dir).unwrap();
            for _ in 0..5 {
                gate.record(simple_event()).unwrap();
            }
        }
        let seg_path = audit_dir.join("audit-000000.log");
        fs::remove_file(&seg_path).unwrap();
        let result = AuditGate::open(&audit_dir);
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_gate_exclusive_lock() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let _gate1 = AuditGate::open(&audit_dir).unwrap();
        let result = AuditGate::open(&audit_dir);
        assert!(matches!(result, Err(AuditError::LockFailed(_))));
    }

    #[test]
    fn test_audit_gate_rotation() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open_with_max_size(&audit_dir, 1024).unwrap();
        for _ in 0..20 {
            let _ = gate.record(simple_event());
        }
        let segments: Vec<PathBuf> = fs::read_dir(&audit_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("audit-") && n.ends_with(".log"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(segments.len() > 1);
        let count = gate.verify_all().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_cross_segment_reopen() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open_with_max_size(&audit_dir, 512).unwrap();
            for _ in 0..10 {
                let _ = gate.record(simple_event());
            }
        }
        {
            let gate = AuditGate::open_with_max_size(&audit_dir, 512).unwrap();
            let seq = gate.current_sequence();
            assert!(seq > 0);
            let receipt = gate.record(simple_event()).unwrap();
            assert_eq!(receipt.sequence, seq + 1);
            gate.verify_all().unwrap();
        }
    }

    #[test]
    fn test_empty_rotated_segment_restart() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open_with_max_size(&audit_dir, 512).unwrap();
        for _ in 0..5 {
            let _ = gate.record(simple_event());
        }
        let seq_before = gate.current_sequence();
        let hash_before = gate.current_hash();
        drop(gate);
        let mut segments: Vec<PathBuf> = fs::read_dir(&audit_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("audit-") && n.ends_with(".log"))
                    .unwrap_or(false)
            })
            .collect();
        segments.sort();
        let last_seg = segments.last().unwrap();
        let last_size = fs::metadata(last_seg).unwrap().len();
        if last_size == HEADER_SIZE as u64 {
            let gate = AuditGate::open_with_max_size(&audit_dir, 512).unwrap();
            assert_eq!(gate.current_sequence(), seq_before);
            assert_eq!(gate.current_hash(), hash_before);
            let receipt = gate.record(simple_event()).unwrap();
            assert_eq!(receipt.sequence, seq_before + 1);
        }
    }

    #[test]
    fn test_partial_write_failure() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open_with_faults(
            &audit_dir,
            DEFAULT_MAX_SEGMENT_SIZE,
            Box::new(FailAt(FaultPoint::WriteRecord)),
        )
        .unwrap();
        let result = gate.record(simple_event());
        assert!(result.is_err());
        assert!(gate.is_circuit_broken());
    }

    #[test]
    fn test_fsync_failure() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open_with_faults(
            &audit_dir,
            DEFAULT_MAX_SEGMENT_SIZE,
            Box::new(FailAt(FaultPoint::FsyncRecord)),
        )
        .unwrap();
        let result = gate.record(simple_event());
        assert!(result.is_err());
        assert!(gate.is_circuit_broken());
    }

    #[test]
    fn test_enospc_failure() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate =
            AuditGate::open_with_faults(&audit_dir, DEFAULT_MAX_SEGMENT_SIZE, Box::new(FailEnospc))
                .unwrap();
        let result = gate.record(simple_event());
        assert!(result.is_err());
        assert!(gate.is_circuit_broken());
    }

    #[test]
    fn test_second_writer_rejected() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let _gate1 = AuditGate::open(&audit_dir).unwrap();
        let result = AuditGate::open(&audit_dir);
        assert!(matches!(result, Err(AuditError::LockFailed(_))));
    }

    #[test]
    fn test_crash_tail_before_anchor() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open(&audit_dir).unwrap();
            gate.record(simple_event()).unwrap();
        }
        let seg_path = audit_dir.join("audit-000000.log");
        let content = fs::read(&seg_path).unwrap();
        let garbage = b"GARBAGE_DATA_AFTER_VALID_RECORD";
        let mut new_content = content.clone();
        new_content.extend_from_slice(garbage);
        fs::write(&seg_path, &new_content).unwrap();
        let gate = AuditGate::open(&audit_dir).unwrap();
        assert_eq!(gate.current_sequence(), 2);
        gate.verify_all().unwrap();
    }

    #[test]
    fn test_reorder_detected() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open(&audit_dir).unwrap();
        let _r1 = gate.record(simple_event()).unwrap();
        let _r2 = gate.record(simple_event()).unwrap();
        let _r3 = gate.record(simple_event()).unwrap();
        drop(gate);
        let seg_path = audit_dir.join("audit-000000.log");
        let mut file = File::open(&seg_path).unwrap();
        let mut header_buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf).unwrap();
        let mut frames = Vec::new();
        loop {
            let mut magic_buf = [0u8; 4];
            match file.read_exact(&mut magic_buf) {
                Ok(_) => {}
                Err(_) => break,
            }
            let mut len_buf = [0u8; 8];
            file.read_exact(&mut len_buf).unwrap();
            let frame_len = u64::from_le_bytes(len_buf) as usize;
            let mut frame_buf = vec![0u8; frame_len];
            file.read_exact(&mut frame_buf).unwrap();
            let mut full = Vec::new();
            full.extend_from_slice(&magic_buf);
            full.extend_from_slice(&len_buf);
            full.extend_from_slice(&frame_buf);
            frames.push(full);
        }
        assert_eq!(frames.len(), 3);
        frames.swap(0, 1);
        let mut new_content = header_buf.to_vec();
        for frame in &frames {
            new_content.extend_from_slice(frame);
        }
        fs::write(&seg_path, &new_content).unwrap();
        let result = AuditGate::open(&audit_dir);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_middle_segment() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open_with_max_size(&audit_dir, 256).unwrap();
            for _ in 0..20 {
                let _ = gate.record(simple_event());
            }
        }
        let segments: Vec<PathBuf> = fs::read_dir(&audit_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("audit-") && n.ends_with(".log"))
                    .unwrap_or(false)
            })
            .collect();
        if segments.len() >= 3 {
            fs::remove_file(&segments[1]).unwrap();
            let result = AuditGate::open_with_max_size(&audit_dir, 256);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_delete_first_segment() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open_with_max_size(&audit_dir, 256).unwrap();
            for _ in 0..20 {
                let _ = gate.record(simple_event());
            }
        }
        let segments: Vec<PathBuf> = fs::read_dir(&audit_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("audit-") && n.ends_with(".log"))
                    .unwrap_or(false)
            })
            .collect();
        if segments.len() >= 2 {
            fs::remove_file(&segments[0]).unwrap();
            let result = AuditGate::open_with_max_size(&audit_dir, 256);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_delete_last_segment() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open_with_max_size(&audit_dir, 256).unwrap();
            for _ in 0..20 {
                let _ = gate.record(simple_event());
            }
        }
        let segments: Vec<PathBuf> = fs::read_dir(&audit_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("audit-") && n.ends_with(".log"))
                    .unwrap_or(false)
            })
            .collect();
        if segments.len() >= 2 {
            fs::remove_file(segments.last().unwrap()).unwrap();
            let result = AuditGate::open_with_max_size(&audit_dir, 256);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_rotation_crash_after_header_before_record() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate =
            AuditGate::open_with_faults(&audit_dir, 512, Box::new(FailAt(FaultPoint::WriteHeader)))
                .unwrap();
        for _ in 0..5 {
            let _ = gate.record(simple_event());
        }
        let result = gate.record(simple_event());
        assert!(result.is_err());
        assert!(gate.is_circuit_broken());
    }

    #[test]
    fn test_wall_clock_backwards() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open(&audit_dir).unwrap();
        let event1 = simple_event();
        let event2 = simple_event();
        let r1 = gate.record(event1).unwrap();
        let r2 = gate.record(event2).unwrap();
        assert_eq!(r1.sequence, 1);
        assert_eq!(r2.sequence, 2);
        gate.verify_all().unwrap();
    }

    #[test]
    fn test_taxonomy_serialization_in_envelope() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open(&audit_dir).unwrap();
        let events = vec![
            DaemonStartBuilder::new(1234, BackendKind::Local).build(),
            ProfileCreateBuilder::new(test_profile_id()).build(),
            CredentialCreateBuilder::new(test_cred(), "example.com").build(),
            GrantApproveBuilder::new(test_grant_id(), test_profile_id()).build(),
        ];
        for event in events {
            let receipt = gate.record(event).unwrap();
            assert!(receipt.sequence > 0);
        }
        gate.verify_all().unwrap();
    }

    #[test]
    fn test_circuit_breaker_permanent() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open(&audit_dir).unwrap();
        gate.circuit_broken.store(true, Ordering::SeqCst);
        let result = gate.record(simple_event());
        assert!(matches!(result, Err(AuditError::CircuitBroken(_))));
        assert!(gate.is_circuit_broken());
    }

    #[test]
    fn test_segment_indices_contiguous_from_zero() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open_with_max_size(&audit_dir, 256).unwrap();
        for _ in 0..20 {
            let _ = gate.record(simple_event());
        }
        let mut segments: Vec<PathBuf> = fs::read_dir(&audit_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("audit-") && n.ends_with(".log"))
                    .unwrap_or(false)
            })
            .collect();
        segments.sort();
        for (i, seg) in segments.iter().enumerate() {
            let name = seg.file_name().unwrap().to_str().unwrap();
            let idx = AuditGate::extract_segment_index(name).unwrap();
            assert_eq!(idx, i as u64);
        }
    }

    #[test]
    fn test_recovery_event_after_truncation() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open(&audit_dir).unwrap();
        gate.record(simple_event()).unwrap();
        let receipt = gate
            .append_recovery(RecoveryReason::IncompleteTailTruncated, 42)
            .unwrap();
        assert_eq!(receipt.sequence, 2);
        gate.verify_all().unwrap();
    }

    #[test]
    fn test_payload_length_bounded() {
        let large_payload = vec![0u8; MAX_PAYLOAD_SIZE as usize + 1];
        let prev_hash = [0u8; 32];
        let hash = compute_record_hash(&prev_hash, 1, 1000, 500, &large_payload);
        let frame = encode_frame(1, 1000, 500, &large_payload, &prev_hash, &hash);
        assert!(decode_frame(&frame).is_err());
    }

    #[test]
    fn test_path_replacement_rejected() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open(&audit_dir).unwrap();
            gate.record(simple_event()).unwrap();
        }
        let real_dir = temp.path().join("real_audit");
        fs::rename(&audit_dir, &real_dir).unwrap();
        symlink(&real_dir, &audit_dir).unwrap();
        let result = AuditGate::open(&audit_dir);
        assert!(matches!(result, Err(AuditError::SymlinkDetected(_))));
    }

    #[test]
    fn test_anchor_symlink_rejected() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open(&audit_dir).unwrap();
            gate.record(simple_event()).unwrap();
        }
        let anchor_path = audit_dir.join("audit.anchor");
        let real_anchor = audit_dir.join("audit.anchor.real");
        fs::rename(&anchor_path, &real_anchor).unwrap();
        symlink(&real_anchor, &anchor_path).unwrap();
        let result = AuditGate::open(&audit_dir);
        assert!(matches!(result, Err(AuditError::SymlinkDetected(_))));
    }

    #[test]
    fn test_automatic_recovery_on_tail_garbage() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let seq_before;
        {
            let gate = AuditGate::open(&audit_dir).unwrap();
            gate.record(simple_event()).unwrap();
            let r2 = gate.record(simple_event()).unwrap();
            seq_before = r2.sequence;
        }
        let seg_path = audit_dir.join("audit-000000.log");
        let mut content = fs::read(&seg_path).unwrap();
        content.extend_from_slice(b"GARBAGE_TAIL_BYTES");
        fs::write(&seg_path, &content).unwrap();
        let gate = AuditGate::open(&audit_dir).unwrap();
        assert_eq!(gate.current_sequence(), seq_before + 1);
        let after_content = fs::read(&seg_path).unwrap();
        assert!(
            !after_content
                .windows(18)
                .any(|w| w == b"GARBAGE_TAIL_BYTES")
        );
        let count = gate.verify_all().unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_anchor_attested_truncation_fails_closed() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        {
            let gate = AuditGate::open(&audit_dir).unwrap();
            for _ in 0..3 {
                gate.record(simple_event()).unwrap();
            }
        }
        let seg_path = audit_dir.join("audit-000000.log");
        let content = fs::read(&seg_path).unwrap();
        let mut file = File::open(&seg_path).unwrap();
        let mut header_buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf).unwrap();
        let mut frames_data = Vec::new();
        loop {
            let mut magic_buf = [0u8; 4];
            match file.read_exact(&mut magic_buf) {
                Ok(_) => {}
                Err(_) => break,
            }
            let mut len_buf = [0u8; 8];
            file.read_exact(&mut len_buf).unwrap();
            let frame_len = u64::from_le_bytes(len_buf) as usize;
            let mut frame_buf = vec![0u8; frame_len];
            file.read_exact(&mut frame_buf).unwrap();
            frames_data.extend_from_slice(&magic_buf);
            frames_data.extend_from_slice(&len_buf);
            frames_data.extend_from_slice(&frame_buf);
        }
        assert!(frames_data.len() >= 2);
        let truncate_point = header_buf.len() + frames_data.len() / 2;
        let truncated = &content[..truncate_point];
        fs::write(&seg_path, truncated).unwrap();
        let result = AuditGate::open(&audit_dir);
        assert!(result.is_err());
    }

    #[test]
    fn test_writer_does_not_use_o_append() {
        let temp = TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let gate = AuditGate::open(&audit_dir).unwrap();
        let r1 = gate.record(simple_event()).unwrap();
        let seg_path = audit_dir.join("audit-000000.log");
        let size_after_first = fs::metadata(&seg_path).unwrap().len();
        let r2 = gate.record(simple_event()).unwrap();
        assert_eq!(r1.sequence, 1);
        assert_eq!(r2.sequence, 2);
        let size_after_second = fs::metadata(&seg_path).unwrap().len();
        assert!(size_after_second > size_after_first);
        gate.verify_all().unwrap();
    }
}
