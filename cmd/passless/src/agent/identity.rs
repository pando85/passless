//! Process and session identity of principals, the daemon's monotonic clock, and the admin
//! authority token (moved here from the removed principal intent store, ADR 0014 P7).

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    pub fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    pub fn as_millis(&self) -> u64 {
        self.0
    }

    pub fn checked_add(&self, duration_ms: u64) -> Option<Self> {
        self.0.checked_add(duration_ms).map(Self)
    }

    pub fn saturating_duration_since(&self, earlier: MonotonicTime) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

pub trait MonotonicClock: Send + Sync {
    fn now(&self) -> MonotonicTime;
}

pub struct SystemClock {
    epoch: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemClock {
    fn now(&self) -> MonotonicTime {
        let elapsed = self.epoch.elapsed();
        MonotonicTime::from_millis(elapsed.as_millis() as u64)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProcessIdentityDigest([u8; 32]);

pub struct SessionIdentityParams {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
    pub start_time: u64,
    pub cgroup_path: String,
    pub ns_user: u64,
    pub ns_pid: u64,
    pub ns_mnt: u64,
}

impl ProcessIdentityDigest {
    pub fn compute(uid: u32, gid: u32, pid: u32, exe_hash: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"passless/process-identity/v1");
        hasher.update(uid.to_le_bytes());
        hasher.update(gid.to_le_bytes());
        hasher.update(pid.to_le_bytes());
        hasher.update(exe_hash);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    pub fn compute_from_session_identity(params: &SessionIdentityParams) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"passless/session-identity/v2\x00");
        hasher.update(params.uid.to_le_bytes());
        hasher.update(params.gid.to_le_bytes());
        hasher.update((params.pid as u32).to_le_bytes());
        hasher.update(params.start_time.to_le_bytes());
        hasher.update((params.cgroup_path.len() as u32).to_le_bytes());
        hasher.update(params.cgroup_path.as_bytes());
        hasher.update(params.ns_user.to_le_bytes());
        hasher.update(params.ns_pid.to_le_bytes());
        hasher.update(params.ns_mnt.to_le_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ProcessIdentityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProcessIdentityDigest")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for ProcessIdentityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Debug, Clone)]
pub struct AdminAuthority {
    _sealed: std::marker::PhantomData<()>,
}

impl AdminAuthority {
    fn new() -> Self {
        Self {
            _sealed: std::marker::PhantomData,
        }
    }
}

static ADMIN_AUTHORITY_TOKEN: AtomicU64 = AtomicU64::new(0);

pub(crate) fn admin_authority() -> AdminAuthority {
    ADMIN_AUTHORITY_TOKEN.fetch_add(1, Ordering::Relaxed);
    AdminAuthority::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monotonic_time_ordering() {
        let t1 = MonotonicTime::from_millis(100);
        let t2 = MonotonicTime::from_millis(200);
        assert!(t1 < t2);
        assert!(t2 > t1);
        assert_eq!(t1, MonotonicTime::from_millis(100));
    }

    #[test]
    fn test_monotonic_time_arithmetic() {
        let t = MonotonicTime::from_millis(100);
        let t2 = t.checked_add(50).unwrap();
        assert_eq!(t2.as_millis(), 150);
        assert_eq!(t2.saturating_duration_since(t), 50);
    }

    #[test]
    fn test_process_identity_digest_deterministic() {
        let d1 = ProcessIdentityDigest::compute(1000, 1000, 42, b"hash");
        let d2 = ProcessIdentityDigest::compute(1000, 1000, 42, b"hash");
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_process_identity_digest_different_inputs() {
        let d1 = ProcessIdentityDigest::compute(1000, 1000, 42, b"hash-a");
        let d2 = ProcessIdentityDigest::compute(1000, 1000, 42, b"hash-b");
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_two_sessions_differ() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 4026531837,
            ns_pid: 4026531836,
            ns_mnt: 4026531840,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 200,
            start_time: 6000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 4026531837,
            ns_pid: 4026531836,
            ns_mnt: 4026531840,
        });
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_same_inputs_same_output() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_differs_by_cgroup() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice/a".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice/b".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_differs_by_ns_inodes() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 4,
            ns_pid: 5,
            ns_mnt: 6,
        });
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_differs_by_uid_gid() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1001,
            gid: 1001,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_differs_by_start_time() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5001,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_domain_separated_from_v1() {
        let d_v1 = ProcessIdentityDigest::compute(1000, 1000, 100, b"test");
        let d_v2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 0,
            cgroup_path: "".to_string(),
            ns_user: 0,
            ns_pid: 0,
            ns_mnt: 0,
        });
        assert_ne!(d_v1, d_v2);
    }
}
