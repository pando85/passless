use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use passless_core::agent::protocol::{DoctorCheck, EndpointDiagnosticState};
use passless_core::agent::{AgentMode, ProfileId};

use super::audit::AuditGate;
use super::browser::{BrowserManifest, ProcessIdentity};
use super::launcher::{ProbeResult, probe_uhid_access};

use passless_core::agent::ProfileDiagnosticReport;

pub trait StartupProbes: Send + Sync {
    fn probe_euid_is_root(&self) -> bool;
    fn probe_uhid(&self) -> ProbeResult;
    fn probe_close_range_available(&self) -> bool;
    fn probe_audit_gate_healthy(&self, audit_path: &Path) -> Result<(), String>;
    fn probe_storage_root(&self, path: &Path, expected_uid: u32) -> Result<(), String>;
    fn probe_browser_runtime_root(&self, path: &Path, expected_uid: u32) -> Result<(), String>;
    fn probe_stale_manifests(&self, runtime_root: &Path) -> StaleManifestResult;
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StaleManifestResult {
    None,
    Quarantined { count: usize },
    Unsafe { count: usize, reason: String },
}

pub struct ProductionProbes;

impl StartupProbes for ProductionProbes {
    fn probe_euid_is_root(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn probe_uhid(&self) -> ProbeResult {
        probe_uhid_access()
    }

    fn probe_close_range_available(&self) -> bool {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                libc::c_uint::MAX as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if ret < 0 {
            let errno = io::Error::last_os_error().raw_os_error();
            errno == Some(libc::EINVAL)
        } else {
            true
        }
    }

    fn probe_audit_gate_healthy(&self, audit_path: &Path) -> Result<(), String> {
        let meta = fs::symlink_metadata(audit_path)
            .map_err(|e| format!("audit path '{}' inaccessible: {}", audit_path.display(), e))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "audit path '{}' is a symlink",
                audit_path.display()
            ));
        }
        if !meta.is_dir() {
            return Err(format!(
                "audit path '{}' is not a directory",
                audit_path.display()
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(format!(
                "audit path '{}' mode is {:o}, expected 700",
                audit_path.display(),
                mode
            ));
        }
        let daemon_uid = unsafe { libc::getuid() };
        if meta.uid() != daemon_uid {
            return Err(format!(
                "audit path '{}' owned by uid {}, expected {}",
                audit_path.display(),
                meta.uid(),
                daemon_uid
            ));
        }
        Ok(())
    }

    fn probe_storage_root(&self, path: &Path, expected_uid: u32) -> Result<(), String> {
        validate_directory_security(path, expected_uid, "storage root")
    }

    fn probe_browser_runtime_root(&self, path: &Path, expected_uid: u32) -> Result<(), String> {
        validate_directory_security(path, expected_uid, "browser runtime root")
    }

    fn probe_stale_manifests(&self, runtime_root: &Path) -> StaleManifestResult {
        scan_and_quarantine_stale_manifests(runtime_root)
    }
}

fn validate_directory_security(path: &Path, expected_uid: u32, label: &str) -> Result<(), String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("{} '{}' inaccessible: {}", label, path.display(), e))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{} '{}' is a symlink", label, path.display()));
    }
    if !meta.is_dir() {
        return Err(format!("{} '{}' is not a directory", label, path.display()));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(format!(
            "{} '{}' mode is {:o}, expected 700",
            label,
            path.display(),
            mode
        ));
    }
    if meta.uid() != expected_uid {
        return Err(format!(
            "{} '{}' owned by uid {}, expected {}",
            label,
            path.display(),
            meta.uid(),
            expected_uid
        ));
    }
    Ok(())
}

fn scan_and_quarantine_stale_manifests(runtime_root: &Path) -> StaleManifestResult {
    let entries = match fs::read_dir(runtime_root) {
        Ok(e) => e,
        Err(_) => return StaleManifestResult::None,
    };

    let mut stale_count = 0usize;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let manifest_path = entry.path().join("browser-manifest.json");
        if !manifest_path.exists() {
            continue;
        }

        let manifest_content = match fs::read_to_string(&manifest_path) {
            Ok(c) => c,
            Err(_) => {
                stale_count += 1;
                continue;
            }
        };

        let manifest: BrowserManifest = match serde_json::from_str(&manifest_content) {
            Ok(m) => m,
            Err(_) => {
                stale_count += 1;
                continue;
            }
        };

        if is_process_alive_verified(manifest.pid, &manifest.process_identity) {
            continue;
        }

        stale_count += 1;
    }

    if stale_count == 0 {
        StaleManifestResult::None
    } else {
        StaleManifestResult::Quarantined { count: stale_count }
    }
}

fn is_process_alive_verified(pid: u32, expected_identity: &ProcessIdentity) -> bool {
    if !expected_identity.is_valid() {
        return false;
    }

    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = match fs::read_to_string(&stat_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let close_paren = match stat_content.rfind(')') {
        Some(p) => p,
        None => return false,
    };
    let after_comm = &stat_content[close_paren + 2..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.len() < 20 {
        return false;
    }
    let start_time: u64 = match fields[19].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };

    start_time == expected_identity.start_time_ticks
}

#[derive(Debug)]
pub struct StartupDiagnosticResult {
    pub checks: Vec<DoctorCheck>,
    pub fatal: Vec<String>,
}

impl StartupDiagnosticResult {
    pub fn is_ok(&self) -> bool {
        self.fatal.is_empty()
    }
}

pub fn run_startup_diagnostics(
    probes: &dyn StartupProbes,
    has_profiles: bool,
    audit_path: Option<&Path>,
    profile_configs: &[(String, ProfileStartupInfo)],
) -> StartupDiagnosticResult {
    let mut checks = Vec::new();
    let mut fatal = Vec::new();

    if has_profiles {
        let euid_ok = probes.probe_euid_is_root();
        checks.push(DoctorCheck {
            name: "daemon_euid_root".into(),
            passed: euid_ok,
            message: if euid_ok {
                "daemon euid is root".into()
            } else {
                "daemon euid is not root; relying on group-based UHID access".into()
            },
        });
    }

    if has_profiles {
        let uhid = probes.probe_uhid();
        let uhid_ok = matches!(uhid, ProbeResult::Allowed { .. });
        checks.push(DoctorCheck {
            name: "uhid_access".into(),
            passed: uhid_ok,
            message: match &uhid {
                ProbeResult::Allowed { path } => format!("{} is accessible", path),
                ProbeResult::Denied { path, errno } => {
                    format!("{} is not accessible (errno {})", path, errno)
                }
            },
        });
        if !uhid_ok {
            fatal.push("/dev/uhid not accessible".into());
        }
    }

    if has_profiles {
        let cr_ok = probes.probe_close_range_available();
        checks.push(DoctorCheck {
            name: "close_range".into(),
            passed: cr_ok,
            message: if cr_ok {
                "close_range syscall available".into()
            } else {
                "close_range syscall not available".into()
            },
        });
        if !cr_ok {
            fatal.push("close_range syscall not available".into());
        }
    }

    if let Some(audit_path) = audit_path {
        match probes.probe_audit_gate_healthy(audit_path) {
            Ok(()) => {
                checks.push(DoctorCheck {
                    name: "audit_gate".into(),
                    passed: true,
                    message: "audit directory is healthy".into(),
                });
            }
            Err(e) => {
                checks.push(DoctorCheck {
                    name: "audit_gate".into(),
                    passed: false,
                    message: e.clone(),
                });
                fatal.push(e);
            }
        }
    }

    for (name, info) in profile_configs {
        for (root_label, root_path, expected_uid) in &info.storage_roots {
            match probes.probe_storage_root(root_path, *expected_uid) {
                Ok(()) => {
                    checks.push(DoctorCheck {
                        name: format!("storage_root.{}.{}", name, root_label),
                        passed: true,
                        message: format!("{} ok", root_label),
                    });
                }
                Err(e) => {
                    checks.push(DoctorCheck {
                        name: format!("storage_root.{}.{}", name, root_label),
                        passed: false,
                        message: e.clone(),
                    });
                    fatal.push(format!("profile '{}': {}", name, e));
                }
            }
        }

        if let Some(ref brt) = info.browser_runtime_root {
            match probes.probe_browser_runtime_root(&brt.path, brt.expected_uid) {
                Ok(()) => {
                    checks.push(DoctorCheck {
                        name: format!("browser_runtime_root.{}", name),
                        passed: true,
                        message: "browser runtime root ok".into(),
                    });
                }
                Err(e) => {
                    checks.push(DoctorCheck {
                        name: format!("browser_runtime_root.{}", name),
                        passed: false,
                        message: e.clone(),
                    });
                    fatal.push(format!("profile '{}': {}", name, e));
                }
            }
        }

        for uid_check in &info.uid_checks {
            checks.push(DoctorCheck {
                name: format!("uid_distinction.{}.{}", name, uid_check.label),
                passed: uid_check.passed,
                message: uid_check.message.clone(),
            });
            if !uid_check.passed {
                fatal.push(format!("profile '{}': {}", name, uid_check.message));
            }
        }

        if let Some(ref brt) = info.browser_runtime_root {
            let stale_result = probes.probe_stale_manifests(&brt.path);
            match stale_result {
                StaleManifestResult::None => {
                    checks.push(DoctorCheck {
                        name: format!("stale_manifests.{}", name),
                        passed: true,
                        message: "no stale browser manifests".into(),
                    });
                }
                StaleManifestResult::Quarantined { count } => {
                    checks.push(DoctorCheck {
                        name: format!("stale_manifests.{}", name),
                        passed: true,
                        message: format!(
                            "{} stale manifest(s) found, process identity not verified",
                            count
                        ),
                    });
                }
                StaleManifestResult::Unsafe { count, reason } => {
                    checks.push(DoctorCheck {
                        name: format!("stale_manifests.{}", name),
                        passed: false,
                        message: format!("{} unsafe stale manifest(s): {}", count, reason),
                    });
                    fatal.push(format!(
                        "profile '{}': unsafe stale browser manifests",
                        name
                    ));
                }
            }
        }

        checks.push(DoctorCheck {
            name: format!("device_identity.{}", name),
            passed: info.device_identity_unique,
            message: if info.device_identity_unique {
                "device identity is unique".into()
            } else {
                "device identity collides with another profile".into()
            },
        });
        if !info.device_identity_unique {
            fatal.push(format!("profile '{}': device identity collision", name));
        }
    }

    StartupDiagnosticResult { checks, fatal }
}

pub struct BrowserRuntimeRootInfo {
    pub path: PathBuf,
    pub expected_uid: u32,
}

pub struct UidCheck {
    pub label: String,
    pub passed: bool,
    pub message: String,
}

pub struct ProfileStartupInfo {
    pub storage_roots: Vec<(String, PathBuf, u32)>,
    pub browser_runtime_root: Option<BrowserRuntimeRootInfo>,
    pub uid_checks: Vec<UidCheck>,
    pub device_identity_unique: bool,
}

pub struct ProfileDiagnosticParams<'a> {
    pub profile_id: &'a ProfileId,
    pub enabled: bool,
    pub mode: AgentMode,
    pub endpoint_has_id: bool,
    pub browser_lease_state: Option<&'a str>,
    pub policy_generation: u64,
    pub audit_gate: &'a AuditGate,
    pub pin_storage_available: bool,
    pub pin_set: bool,
    pub require_uv: bool,
}

pub fn build_profile_diagnostic_report(
    params: ProfileDiagnosticParams<'_>,
) -> ProfileDiagnosticReport {
    let ProfileDiagnosticParams {
        profile_id,
        enabled,
        mode,
        endpoint_has_id,
        browser_lease_state,
        policy_generation,
        audit_gate,
        pin_storage_available,
        pin_set,
        require_uv,
    } = params;
    let endpoint_state = match mode {
        AgentMode::Isolated => {
            if endpoint_has_id {
                EndpointDiagnosticState::Ready
            } else {
                EndpointDiagnosticState::Unavailable
            }
        }
    };

    let audit_ok = audit_gate.ping();

    let mut checks = Vec::new();

    checks.push(DoctorCheck {
        name: "enabled".into(),
        passed: enabled,
        message: if enabled {
            "profile is enabled".into()
        } else {
            "profile is disabled".into()
        },
    });

    checks.push(DoctorCheck {
        name: "endpoint".into(),
        passed: !matches!(endpoint_state, EndpointDiagnosticState::Unavailable),
        message: format!("endpoint state: {}", endpoint_state),
    });

    if let Some(lease_state) = browser_lease_state {
        checks.push(DoctorCheck {
            name: "browser_lease".into(),
            passed: true,
            message: format!("browser lease: {}", lease_state),
        });
    }

    checks.push(DoctorCheck {
        name: "policy_generation".into(),
        passed: true,
        message: format!("policy generation: {}", policy_generation),
    });

    checks.push(DoctorCheck {
        name: "audit_gate".into(),
        passed: audit_ok,
        message: if audit_ok {
            "audit gate is healthy".into()
        } else {
            "audit gate is not healthy".into()
        },
    });

    checks.push(DoctorCheck {
        name: "pin_storage".into(),
        passed: pin_storage_available,
        message: if pin_storage_available {
            "PIN storage is available".into()
        } else {
            "PIN storage is not available".into()
        },
    });

    checks.push(DoctorCheck {
        name: "pin_set".into(),
        passed: if require_uv { pin_set } else { true },
        message: if pin_set {
            "PIN is set".into()
        } else if require_uv {
            "PIN is not set but require_uv is enabled".into()
        } else {
            "PIN is not set".into()
        },
    });

    let mode_str = format!("{:?}", mode);

    ProfileDiagnosticReport {
        profile_id: profile_id.to_string(),
        enabled,
        mode: mode_str,
        endpoint_state,
        browser_lease_state: browser_lease_state.map(|s| s.to_string()),
        policy_generation,
        audit_gate_healthy: audit_ok,
        pin_storage_available,
        pin_set,
        checks,
    }
}

pub fn compute_device_identity_uniqueness(
    profiles: &[(String, DeviceIdentityKey)],
) -> Vec<(String, bool)> {
    let mut keys: Vec<String> = Vec::new();

    for (_name, key) in profiles {
        let composite = format!(
            "{}:{}:{}:{}:{}",
            key.name, key.phys, key.uniq, key.vendor_id, key.product_id
        );
        keys.push(composite);
    }

    let mut result = Vec::new();
    for (i, (name, _)) in profiles.iter().enumerate() {
        let key = &keys[i];
        let unique = profiles.iter().enumerate().all(|(j, _)| {
            if i == j {
                return true;
            }
            keys[j] != *key
        });
        result.push((name.clone(), unique));
    }

    result
}

pub struct DeviceIdentityKey {
    pub name: String,
    pub phys: String,
    pub uniq: String,
    pub vendor_id: u16,
    pub product_id: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    pub struct MockProbes {
        pub euid_is_root: bool,
        pub uhid_result: ProbeResult,
        pub close_range_ok: bool,
        pub audit_healthy: bool,
        pub storage_results: Mutex<Vec<Result<(), String>>>,
        pub browser_root_results: Mutex<Vec<Result<(), String>>>,
        pub stale_result: StaleManifestResult,
    }

    impl MockProbes {
        pub fn all_healthy() -> Self {
            Self {
                euid_is_root: true,
                uhid_result: ProbeResult::Allowed {
                    path: "/dev/uhid".into(),
                },
                close_range_ok: true,
                audit_healthy: true,
                storage_results: Mutex::new(Vec::new()),
                browser_root_results: Mutex::new(Vec::new()),
                stale_result: StaleManifestResult::None,
            }
        }

        pub fn no_uhid() -> Self {
            Self {
                euid_is_root: true,
                uhid_result: ProbeResult::Denied {
                    path: "/dev/uhid".into(),
                    errno: libc::EACCES,
                },
                close_range_ok: true,
                audit_healthy: true,
                storage_results: Mutex::new(Vec::new()),
                browser_root_results: Mutex::new(Vec::new()),
                stale_result: StaleManifestResult::None,
            }
        }

        pub fn no_close_range() -> Self {
            Self {
                euid_is_root: true,
                uhid_result: ProbeResult::Allowed {
                    path: "/dev/uhid".into(),
                },
                close_range_ok: false,
                audit_healthy: true,
                storage_results: Mutex::new(Vec::new()),
                browser_root_results: Mutex::new(Vec::new()),
                stale_result: StaleManifestResult::None,
            }
        }

        pub fn not_root() -> Self {
            Self {
                euid_is_root: false,
                uhid_result: ProbeResult::Allowed {
                    path: "/dev/uhid".into(),
                },
                close_range_ok: true,
                audit_healthy: true,
                storage_results: Mutex::new(Vec::new()),
                browser_root_results: Mutex::new(Vec::new()),
                stale_result: StaleManifestResult::None,
            }
        }

        pub fn audit_broken() -> Self {
            Self {
                euid_is_root: true,
                uhid_result: ProbeResult::Allowed {
                    path: "/dev/uhid".into(),
                },
                close_range_ok: true,
                audit_healthy: false,
                storage_results: Mutex::new(Vec::new()),
                browser_root_results: Mutex::new(Vec::new()),
                stale_result: StaleManifestResult::None,
            }
        }

        pub fn unsafe_perms() -> Self {
            Self {
                euid_is_root: true,
                uhid_result: ProbeResult::Allowed {
                    path: "/dev/uhid".into(),
                },
                close_range_ok: true,
                audit_healthy: true,
                storage_results: Mutex::new(vec![Err(
                    "storage root '/tmp/x' mode is 755, expected 700".into(),
                )]),
                browser_root_results: Mutex::new(Vec::new()),
                stale_result: StaleManifestResult::None,
            }
        }

        pub fn stale_verified_process() -> Self {
            Self {
                euid_is_root: true,
                uhid_result: ProbeResult::Allowed {
                    path: "/dev/uhid".into(),
                },
                close_range_ok: true,
                audit_healthy: true,
                storage_results: Mutex::new(Vec::new()),
                browser_root_results: Mutex::new(Vec::new()),
                stale_result: StaleManifestResult::Unsafe {
                    count: 1,
                    reason: "verified process still running".into(),
                },
            }
        }
    }

    impl StartupProbes for MockProbes {
        fn probe_euid_is_root(&self) -> bool {
            self.euid_is_root
        }

        fn probe_uhid(&self) -> ProbeResult {
            self.uhid_result.clone()
        }

        fn probe_close_range_available(&self) -> bool {
            self.close_range_ok
        }

        fn probe_audit_gate_healthy(&self, _audit_path: &Path) -> Result<(), String> {
            if self.audit_healthy {
                Ok(())
            } else {
                Err("audit directory mode mismatch".into())
            }
        }

        fn probe_storage_root(&self, _path: &Path, _expected_uid: u32) -> Result<(), String> {
            let mut results = self.storage_results.lock().unwrap();
            if results.is_empty() {
                Ok(())
            } else {
                results.remove(0)
            }
        }

        fn probe_browser_runtime_root(
            &self,
            _path: &Path,
            _expected_uid: u32,
        ) -> Result<(), String> {
            let mut results = self.browser_root_results.lock().unwrap();
            if results.is_empty() {
                Ok(())
            } else {
                results.remove(0)
            }
        }

        fn probe_stale_manifests(&self, _runtime_root: &Path) -> StaleManifestResult {
            self.stale_result.clone()
        }
    }

    fn make_profile_info() -> ProfileStartupInfo {
        ProfileStartupInfo {
            storage_roots: vec![("credential".into(), PathBuf::from("/tmp/creds"), 1000)],
            browser_runtime_root: Some(BrowserRuntimeRootInfo {
                path: PathBuf::from("/tmp/browser"),
                expected_uid: 1000,
            }),
            uid_checks: vec![UidCheck {
                label: "principal_vs_daemon".into(),
                passed: true,
                message: "principal uid differs from daemon".into(),
            }],
            device_identity_unique: true,
        }
    }

    #[test]
    fn test_healthy_startup_no_profiles() {
        let probes = MockProbes::all_healthy();
        let result = run_startup_diagnostics(&probes, false, None, &[]);
        assert!(result.is_ok());
        assert!(result.checks.is_empty());
    }

    #[test]
    fn test_healthy_startup_with_profile() {
        let probes = MockProbes::all_healthy();
        let profiles = vec![("test".into(), make_profile_info())];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(result.is_ok(), "fatal: {:?}", result.fatal);
        assert!(result.checks.iter().all(|c| c.passed));
    }

    #[test]
    fn test_no_uhid_is_fatal() {
        let probes = MockProbes::no_uhid();
        let profiles = vec![("test".into(), make_profile_info())];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(!result.is_ok());
        assert!(result.fatal.iter().any(|f| f.contains("uhid")));
        let uhid_check = result
            .checks
            .iter()
            .find(|c| c.name == "uhid_access")
            .unwrap();
        assert!(!uhid_check.passed);
    }

    #[test]
    fn test_no_close_range_is_fatal() {
        let probes = MockProbes::no_close_range();
        let profiles = vec![("test".into(), make_profile_info())];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(!result.is_ok());
        assert!(result.fatal.iter().any(|f| f.contains("close_range")));
    }

    #[test]
    fn test_not_root_nonfatal_when_uhid_accessible() {
        let probes = MockProbes::not_root();
        let profiles = vec![("test".into(), make_profile_info())];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(result.is_ok());
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "daemon_euid_root" && !c.passed)
        );
    }

    #[test]
    fn test_not_root_nonfatal_without_profiles() {
        let probes = MockProbes::not_root();
        let result = run_startup_diagnostics(&probes, false, None, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_same_uid_is_fatal() {
        let probes = MockProbes::all_healthy();
        let mut info = make_profile_info();
        info.uid_checks = vec![UidCheck {
            label: "principal_vs_daemon".into(),
            passed: false,
            message: "principal uid 0 same as daemon uid 0".into(),
        }];
        let profiles = vec![("test".into(), info)];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(!result.is_ok());
        assert!(result.fatal.iter().any(|f| f.contains("same as daemon")));
    }

    #[test]
    fn test_unsafe_perms_is_fatal() {
        let probes = MockProbes::unsafe_perms();
        let profiles = vec![("test".into(), make_profile_info())];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(!result.is_ok());
        assert!(result.fatal.iter().any(|f| f.contains("mode")));
    }

    #[test]
    fn test_stale_verified_process_is_fatal() {
        let probes = MockProbes::stale_verified_process();
        let profiles = vec![("test".into(), make_profile_info())];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(!result.is_ok());
        assert!(result.fatal.iter().any(|f| f.contains("stale")));
    }

    #[test]
    fn test_audit_broken_is_fatal() {
        let probes = MockProbes::audit_broken();
        let profiles = vec![("test".into(), make_profile_info())];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(!result.is_ok());
        assert!(result.fatal.iter().any(|f| f.contains("audit")));
    }

    #[test]
    fn test_device_identity_collision_detected() {
        let probes = MockProbes::all_healthy();
        let mut info = make_profile_info();
        info.device_identity_unique = false;
        let profiles = vec![("test".into(), info)];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(!result.is_ok());
        assert!(result.fatal.iter().any(|f| f.contains("collision")));
    }

    #[test]
    fn test_compute_device_identity_uniqueness_all_unique() {
        let profiles = vec![
            (
                "a".into(),
                DeviceIdentityKey {
                    name: "n1".into(),
                    phys: "p1".into(),
                    uniq: "u1".into(),
                    vendor_id: 1,
                    product_id: 1,
                },
            ),
            (
                "b".into(),
                DeviceIdentityKey {
                    name: "n2".into(),
                    phys: "p2".into(),
                    uniq: "u2".into(),
                    vendor_id: 2,
                    product_id: 2,
                },
            ),
        ];
        let result = compute_device_identity_uniqueness(&profiles);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|(_, unique)| *unique));
    }

    #[test]
    fn test_compute_device_identity_uniqueness_collision() {
        let key = DeviceIdentityKey {
            name: "same".into(),
            phys: "same".into(),
            uniq: "same".into(),
            vendor_id: 1,
            product_id: 2,
        };
        let profiles = vec![
            (
                "a".into(),
                DeviceIdentityKey {
                    name: key.name.clone(),
                    phys: key.phys.clone(),
                    uniq: key.uniq.clone(),
                    vendor_id: key.vendor_id,
                    product_id: key.product_id,
                },
            ),
            (
                "b".into(),
                DeviceIdentityKey {
                    name: key.name.clone(),
                    phys: key.phys.clone(),
                    uniq: key.uniq.clone(),
                    vendor_id: key.vendor_id,
                    product_id: key.product_id,
                },
            ),
        ];
        let result = compute_device_identity_uniqueness(&profiles);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|(_, unique)| !*unique));
    }

    #[test]
    fn test_profile_diagnostic_report_isolated_ready() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit = AuditGate::open(dir.path()).unwrap();
        let pid = ProfileId::new("test").unwrap();

        let report = build_profile_diagnostic_report(ProfileDiagnosticParams {
            profile_id: &pid,
            enabled: true,
            mode: AgentMode::Isolated,
            endpoint_has_id: true,
            browser_lease_state: None,
            policy_generation: 5,
            audit_gate: &audit,
            pin_storage_available: true,
            pin_set: true,
            require_uv: false,
        });

        assert!(report.is_healthy());
        assert_eq!(report.endpoint_state, EndpointDiagnosticState::Ready);
        assert!(report.audit_gate_healthy);
        assert_eq!(report.policy_generation, 5);
        assert!(report.pin_storage_available);
        assert!(report.pin_set);
    }

    #[test]
    fn test_profile_diagnostic_report_disabled_unhealthy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit = AuditGate::open(dir.path()).unwrap();
        let pid = ProfileId::new("disabled").unwrap();

        let report = build_profile_diagnostic_report(ProfileDiagnosticParams {
            profile_id: &pid,
            enabled: false,
            mode: AgentMode::Isolated,
            endpoint_has_id: false,
            browser_lease_state: None,
            policy_generation: 0,
            audit_gate: &audit,
            pin_storage_available: true,
            pin_set: false,
            require_uv: false,
        });

        assert!(!report.is_healthy());
        assert_eq!(report.endpoint_state, EndpointDiagnosticState::Unavailable);
    }

    #[test]
    fn test_profile_diagnostic_report_require_uv_without_pin_unhealthy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit = AuditGate::open(dir.path()).unwrap();
        let pid = ProfileId::new("require-uv-no-pin").unwrap();

        let report = build_profile_diagnostic_report(ProfileDiagnosticParams {
            profile_id: &pid,
            enabled: true,
            mode: AgentMode::Isolated,
            endpoint_has_id: true,
            browser_lease_state: None,
            policy_generation: 1,
            audit_gate: &audit,
            pin_storage_available: true,
            pin_set: false,
            require_uv: true,
        });

        assert!(!report.is_healthy());
        let pin_set_check = report.checks.iter().find(|c| c.name == "pin_set").unwrap();
        assert!(!pin_set_check.passed);
        assert!(pin_set_check.message.contains("require_uv"));
    }

    #[test]
    fn test_profile_diagnostic_report_pin_storage_unavailable_unhealthy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit = AuditGate::open(dir.path()).unwrap();
        let pid = ProfileId::new("no-pin-storage").unwrap();

        let report = build_profile_diagnostic_report(ProfileDiagnosticParams {
            profile_id: &pid,
            enabled: true,
            mode: AgentMode::Isolated,
            endpoint_has_id: true,
            browser_lease_state: None,
            policy_generation: 1,
            audit_gate: &audit,
            pin_storage_available: false,
            pin_set: false,
            require_uv: false,
        });

        assert!(!report.is_healthy());
        let pin_storage_check = report
            .checks
            .iter()
            .find(|c| c.name == "pin_storage")
            .unwrap();
        assert!(!pin_storage_check.passed);
    }

    #[test]
    fn test_stale_manifest_result_none_is_nonfatal() {
        let probes = MockProbes::all_healthy();
        let profiles = vec![("test".into(), make_profile_info())];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(result.is_ok());
        let check = result
            .checks
            .iter()
            .find(|c| c.name == "stale_manifests.test")
            .unwrap();
        assert!(check.passed);
    }

    #[test]
    fn test_stale_manifest_quarantined_is_nonfatal() {
        let mut probes = MockProbes::all_healthy();
        probes.stale_result = StaleManifestResult::Quarantined { count: 2 };
        let profiles = vec![("test".into(), make_profile_info())];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(result.is_ok());
        let check = result
            .checks
            .iter()
            .find(|c| c.name == "stale_manifests.test")
            .unwrap();
        assert!(check.passed);
        assert!(check.message.contains("2"));
    }

    #[test]
    fn test_probe_close_range_preserves_stdin() {
        use std::os::unix::io::AsRawFd;
        let stdin_fd = std::io::stdin().as_raw_fd();
        let dup_fd = unsafe { libc::dup(stdin_fd) };
        assert!(dup_fd >= 0, "dup(stdin) failed");

        let mut stat_before = unsafe { std::mem::zeroed() };
        let ret_before = unsafe { libc::fstat(stdin_fd, &mut stat_before) };
        assert_eq!(ret_before, 0, "fstat(stdin) before probe failed");

        let probes = ProductionProbes;
        let _ = probes.probe_close_range_available();

        let mut stat_after = unsafe { std::mem::zeroed() };
        let ret_after = unsafe { libc::fstat(stdin_fd, &mut stat_after) };
        assert_eq!(
            ret_after, 0,
            "fstat(stdin) after probe failed - stdin was closed!"
        );
        assert_eq!(stat_before.st_dev, stat_after.st_dev);
        assert_eq!(stat_before.st_ino, stat_after.st_ino);

        unsafe { libc::close(dup_fd) };
    }
}
