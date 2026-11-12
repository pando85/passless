use std::fs;
use std::io;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use passless_core::agent::protocol::DoctorCheck;
use passless_core::agent::{AgentConfig, AgentMode, AgentProfileConfig, ProfileId, RuleAction};

use super::audit::AuditGate;
use super::browser::{BrowserManifest, ProcessIdentity};
use super::deployment::DeploymentAxes;
use super::granted_rules::ProfileGrants;

use passless_core::agent::ProfileDiagnosticReport;

pub trait StartupProbes: Send + Sync {
    fn probe_euid_is_root(&self) -> bool;
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
    /// Non-fatal findings the daemon logs at start, such as the shared-UID `isolated` warning of
    /// ADR 0014 section 13.
    pub warnings: Vec<String>,
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
    let mut warnings = Vec::new();

    if has_profiles {
        let euid_ok = probes.probe_euid_is_root();
        checks.push(DoctorCheck {
            name: "daemon_euid_root".into(),
            passed: euid_ok,
            message: if euid_ok {
                "daemon euid is root".into()
            } else {
                "daemon euid is not root; running without principal isolation".into()
            },
        });
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
        // Both deployment axes (ADR 0014 section 13). No combination is fatal here: a principal
        // that shares the daemon's UID is a supported deployment, and only `isolated` warns.
        checks.extend(info.deployment.checks(Some(name)));
        if let Some(warning) = info.deployment.isolated_shared_uid_warning() {
            warnings.push(format!("profile '{name}': {warning}"));
        }

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
    }

    StartupDiagnosticResult {
        checks,
        fatal,
        warnings,
    }
}

/// What running the installed `sign-proxy --version` gave (plan V-L5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayVersionProbe {
    /// The relay ran and printed this version.
    Found { path: PathBuf, version: String },
    /// No relay where the launcher looks for it.
    Missing { path: Option<PathBuf> },
    /// The relay exists but `--version` failed.
    Failed { path: PathBuf, error: String },
}

/// Runs the installed relay's `--version`, from where the browser launcher finds it.
pub trait RelayProbe: Send + Sync {
    fn probe_relay_version(&self) -> RelayVersionProbe;
}

/// How long `sign-proxy --version` may take.
const RELAY_VERSION_TIMEOUT: Duration = Duration::from_secs(5);
/// Most bytes of `--version` output kept.
const RELAY_VERSION_MAX_LEN: usize = 128;

pub struct ProductionRelayProbe;

impl RelayProbe for ProductionRelayProbe {
    fn probe_relay_version(&self) -> RelayVersionProbe {
        let Some(path) = super::browser::installed_sign_proxy_path() else {
            return RelayVersionProbe::Missing { path: None };
        };
        if !path.is_file() {
            return RelayVersionProbe::Missing { path: Some(path) };
        }
        match run_relay_version(&path) {
            Ok(version) => RelayVersionProbe::Found { path, version },
            Err(error) => RelayVersionProbe::Failed { path, error },
        }
    }
}

fn run_relay_version(path: &Path) -> Result<String, String> {
    let mut child = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run it: {e}"))?;
    let deadline = Instant::now() + RELAY_VERSION_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("--version did not finish".to_string());
            }
            Err(e) => return Err(format!("waiting for it failed: {e}")),
        }
    };
    let mut output = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let _ = stdout
            .take(RELAY_VERSION_MAX_LEN as u64)
            .read_to_end(&mut output);
    }
    if !status.success() {
        return Err(format!("--version exited with {status}"));
    }
    let version = String::from_utf8_lossy(&output).trim().to_string();
    if version.is_empty() {
        return Err("--version printed nothing".to_string());
    }
    Ok(version)
}

/// The `relay_version` doctor check: the installed relay's build version against the daemon's.
/// A missing or broken relay fails (a launch fails without it); a different version passes with
/// a warning, like the version skew a hello reports (plan V-L5).
pub fn relay_version_check(probe: &dyn RelayProbe, daemon_version: &str) -> DoctorCheck {
    let (passed, message) = match probe.probe_relay_version() {
        RelayVersionProbe::Found { path, version } if version == daemon_version => (
            true,
            format!(
                "sign-proxy {} matches the daemon ({})",
                path.display(),
                daemon_version
            ),
        ),
        RelayVersionProbe::Found { path, version } => (
            true,
            format!(
                "warning: sign-proxy {} is version {} but the daemon is {}; reinstall passless \
                 so both come from the same build",
                path.display(),
                version,
                daemon_version
            ),
        ),
        RelayVersionProbe::Missing { path } => (
            false,
            format!(
                "sign-proxy is missing{}; managed browsers cannot launch without it. Reinstall \
                 passless so that sign-proxy is next to the passless executable",
                path.map(|p| format!(" at {}", p.display()))
                    .unwrap_or_default()
            ),
        ),
        RelayVersionProbe::Failed { path, error } => (
            false,
            format!("sign-proxy {} is not usable: {}", path.display(), error),
        ),
    };
    DoctorCheck {
        name: "relay_version".into(),
        passed,
        message,
    }
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
    pub deployment: DeploymentAxes,
}

pub struct ProfileDiagnosticParams<'a> {
    pub profile_id: &'a ProfileId,
    pub enabled: bool,
    pub mode: AgentMode,
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
        browser_lease_state,
        policy_generation,
        audit_gate,
        pin_storage_available,
        pin_set,
        require_uv,
    } = params;
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
        browser_lease_state: browser_lease_state.map(|s| s.to_string()),
        policy_generation,
        audit_gate_healthy: audit_ok,
        pin_storage_available,
        pin_set,
        checks,
    }
}

/// The profile's granted-rules store (ADR 0014 section 8.4). A disabled store fails the check:
/// escalation is denied with `grants_unavailable` and no grant is honored until it is fixed.
pub fn granted_rules_check(view: Option<&ProfileGrants>, path: &Path) -> DoctorCheck {
    match view {
        Some(ProfileGrants::Enabled(rules)) => DoctorCheck {
            name: "granted_rules".into(),
            passed: true,
            message: format!("{} granted rule(s) in {}", rules.len(), path.display()),
        },
        Some(ProfileGrants::Disabled(reason)) => DoctorCheck {
            name: "granted_rules".into(),
            passed: false,
            message: format!(
                "granted rules disabled (fail closed): {reason}; fix or remove the file and \
                 restart the daemon"
            ),
        },
        None => DoctorCheck {
            name: "granted_rules".into(),
            passed: false,
            message: "no granted-rules store for this profile".into(),
        },
    }
}

/// Whether the escalation configuration can reach a notification user (ADR 0014 section 8.2).
///
/// A root daemon without `agents.notify_user` cannot prompt: the check fails when the profile has
/// a `request` rule (those requests are denied with `escalation_unavailable`) and only warns
/// otherwise. A `notify_user` the daemon cannot use (unknown, or another user than a non-root
/// daemon's own, or a principal or browser user of a root daemon) fails.
pub fn escalation_check(
    config: &AgentConfig,
    profile: &AgentProfileConfig,
    daemon_uid: u32,
) -> DoctorCheck {
    if let Err(e) =
        config.validate_escalation(daemon_uid, &passless_core::agent::config::lookup_user_uid)
    {
        return DoctorCheck {
            name: "escalation".into(),
            passed: false,
            message: e.to_string(),
        };
    }
    let requests = profile.rules.iter().any(|rule| {
        rule.authenticate == RuleAction::Request || rule.register == RuleAction::Request
    });
    match config.escalation_unavailable_reason(daemon_uid) {
        Some(reason) => DoctorCheck {
            name: "escalation".into(),
            passed: !requests,
            message: if requests {
                reason
            } else {
                format!("warning: {reason}")
            },
        },
        None => DoctorCheck {
            name: "escalation".into(),
            passed: true,
            message: match &config.notify_user {
                Some(user) => format!("escalation prompts go to '{user}'"),
                None => "escalation prompts go to the daemon user's session bus".into(),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    pub struct MockProbes {
        pub euid_is_root: bool,
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
            deployment: DeploymentAxes::new(AgentMode::Isolated, 1001, 1000),
            storage_roots: vec![("credential".into(), PathBuf::from("/tmp/creds"), 1000)],
            browser_runtime_root: Some(BrowserRuntimeRootInfo {
                path: PathBuf::from("/tmp/browser"),
                expected_uid: 1000,
            }),
            uid_checks: vec![UidCheck {
                label: "principal_not_root".into(),
                passed: true,
                message: "principal is not root".into(),
            }],
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
        // Agents have no UHID route (ADR 0014 section 5): no UHID or device identity check remains.
        assert!(
            !result
                .checks
                .iter()
                .any(|c| c.name == "uhid_access" || c.name.starts_with("device_identity")),
            "{:?}",
            result.checks
        );
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
    fn test_not_root_nonfatal() {
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

    // ADR 0014 section 13: a principal that shares the daemon's UID is a supported deployment, so
    // the relationship is reported as an axis and is never fatal by itself. (This test used to
    // assert that a `principal_vs_daemon` uid check failing on "same as daemon" was fatal.) A
    // principal that is root stays fatal through its own `principal_not_root` check.
    #[test]
    fn test_same_uid_is_reported_and_not_fatal() {
        let probes = MockProbes::all_healthy();
        for mode in [AgentMode::SameUser, AgentMode::Isolated] {
            let mut info = make_profile_info();
            info.deployment = DeploymentAxes::new(mode, 1000, 1000);
            info.uid_checks.clear();
            let profiles = vec![("test".into(), info)];
            let result =
                run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
            assert!(result.is_ok(), "{mode}: fatal: {:?}", result.fatal);
            let axes = result
                .checks
                .iter()
                .find(|c| c.name == "deployment_axes.test")
                .expect("axes check");
            assert!(axes.passed);
            assert!(axes.message.contains(&format!("mode: {mode}")));
            assert!(axes.message.contains("principal_relationship: shared-uid"));
            // Only `isolated` warns, in the checks and in the startup warnings.
            let warned = result
                .checks
                .iter()
                .any(|c| c.name == "isolated_shared_uid.test" && c.passed);
            assert_eq!(warned, mode == AgentMode::Isolated, "{mode}");
            assert_eq!(result.warnings.len(), usize::from(warned), "{mode}");
        }
    }

    #[test]
    fn test_distinct_uid_reports_the_axes_without_a_warning() {
        let probes = MockProbes::all_healthy();
        for mode in [AgentMode::SameUser, AgentMode::Isolated] {
            let mut info = make_profile_info();
            info.deployment = DeploymentAxes::new(mode, 1001, 1000);
            let profiles = vec![("test".into(), info)];
            let result =
                run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
            assert!(result.is_ok(), "{mode}: fatal: {:?}", result.fatal);
            let axes = result
                .checks
                .iter()
                .find(|c| c.name == "deployment_axes.test")
                .expect("axes check");
            assert!(
                axes.message
                    .contains("principal_relationship: distinct-uid")
            );
            assert!(result.warnings.is_empty(), "{mode}: {:?}", result.warnings);
            assert!(
                !result
                    .checks
                    .iter()
                    .any(|c| c.name.starts_with("isolated_shared_uid"))
            );
        }
    }

    #[test]
    fn test_principal_root_is_still_fatal() {
        let probes = MockProbes::all_healthy();
        let mut info = make_profile_info();
        info.deployment = DeploymentAxes::new(AgentMode::Isolated, 0, 0);
        info.uid_checks = vec![UidCheck {
            label: "principal_not_root".into(),
            passed: false,
            message: "principal must not be root".into(),
        }];
        let profiles = vec![("test".into(), info)];
        let result =
            run_startup_diagnostics(&probes, true, Some(Path::new("/tmp/audit")), &profiles);
        assert!(!result.is_ok());
        assert!(
            result
                .fatal
                .iter()
                .any(|f| f.contains("principal must not be root"))
        );
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
    fn test_profile_diagnostic_report_isolated_ready() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit = AuditGate::open(dir.path()).unwrap();
        let pid = ProfileId::new("test").unwrap();

        let report = build_profile_diagnostic_report(ProfileDiagnosticParams {
            profile_id: &pid,
            enabled: true,
            mode: AgentMode::Isolated,
            browser_lease_state: None,
            policy_generation: 5,
            audit_gate: &audit,
            pin_storage_available: true,
            pin_set: true,
            require_uv: false,
        });

        assert!(report.is_healthy());
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
            browser_lease_state: None,
            policy_generation: 0,
            audit_gate: &audit,
            pin_storage_available: true,
            pin_set: false,
            require_uv: false,
        });

        assert!(!report.is_healthy());
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

    struct MockRelayProbe(RelayVersionProbe);

    impl RelayProbe for MockRelayProbe {
        fn probe_relay_version(&self) -> RelayVersionProbe {
            self.0.clone()
        }
    }

    const DAEMON_VERSION: &str = "0.21.0+abc1234";

    #[test]
    fn test_relay_version_check_matching_version_passes() {
        let check = relay_version_check(
            &MockRelayProbe(RelayVersionProbe::Found {
                path: PathBuf::from("/usr/bin/sign-proxy"),
                version: DAEMON_VERSION.to_string(),
            }),
            DAEMON_VERSION,
        );
        assert_eq!(check.name, "relay_version");
        assert!(check.passed);
        assert!(check.message.contains("matches"), "{}", check.message);
    }

    #[test]
    fn test_relay_version_check_mismatch_is_a_warning() {
        let check = relay_version_check(
            &MockRelayProbe(RelayVersionProbe::Found {
                path: PathBuf::from("/usr/bin/sign-proxy"),
                version: "0.20.0+def5678".to_string(),
            }),
            DAEMON_VERSION,
        );
        assert!(check.passed, "skew is not fatal (plan V-L5)");
        assert!(check.message.starts_with("warning:"), "{}", check.message);
        assert!(
            check.message.contains("0.20.0+def5678"),
            "{}",
            check.message
        );
        assert!(check.message.contains(DAEMON_VERSION), "{}", check.message);
    }

    #[test]
    fn test_relay_version_check_missing_or_broken_relay_fails() {
        for probe in [
            RelayVersionProbe::Missing {
                path: Some(PathBuf::from("/usr/bin/sign-proxy")),
            },
            RelayVersionProbe::Missing { path: None },
            RelayVersionProbe::Failed {
                path: PathBuf::from("/usr/bin/sign-proxy"),
                error: "--version exited with exit status: 1".to_string(),
            },
        ] {
            let check = relay_version_check(&MockRelayProbe(probe.clone()), DAEMON_VERSION);
            assert!(!check.passed, "{probe:?}");
            assert!(check.message.contains("sign-proxy"), "{}", check.message);
        }
    }

    #[test]
    fn test_run_relay_version_reads_the_printed_version() {
        let dir = tempfile::tempdir().unwrap();
        let script = |name: &str, body: &str| {
            let path = dir.path().join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        // A script just written can be briefly busy when another test thread forks meanwhile.
        let run = |path: &Path| {
            for _ in 0..20 {
                match run_relay_version(path) {
                    Err(e) if e.contains("Text file busy") => {
                        std::thread::sleep(std::time::Duration::from_millis(50))
                    }
                    other => return other,
                }
            }
            run_relay_version(path)
        };
        let good = script(
            "sign-proxy",
            "#!/bin/sh\n[ \"$1\" = --version ] && echo 1.2.3+abc\n",
        );
        assert_eq!(run(&good).unwrap(), "1.2.3+abc");
        let failing = script("failing-sign-proxy", "#!/bin/sh\nexit 3\n");
        assert!(run(&failing).is_err());
    }

    fn escalation_config(notify_user: Option<&str>, request: bool) -> AgentConfig {
        let action = if request { "request" } else { "allow" };
        let mut config = AgentConfig::from_toml_str(
            &format!(
                "[agents]\nenabled = true\n\n[agents.profiles.p]\nmode = \"same-user\"\n\
                 principal_user = \"root\"\n\n[[agents.profiles.p.rules]]\n\
                 rp_id = \"example.com\"\nauthenticate = \"{action}\"\nregister = \"deny\"\n"
            ),
            "test",
        )
        .unwrap();
        config.notify_user = notify_user.map(str::to_string);
        config
    }

    #[test]
    fn escalation_check_fails_for_a_root_daemon_without_notify_user() {
        let config = escalation_config(None, true);
        let check = escalation_check(&config, &config.profiles["p"], 0);
        assert!(!check.passed, "{check:?}");
        assert!(check.message.contains("notify_user"), "{check:?}");

        // Without a `request` rule nothing needs a prompt: only a warning.
        let config = escalation_config(None, false);
        let check = escalation_check(&config, &config.profiles["p"], 0);
        assert!(check.passed, "{check:?}");
        assert!(check.message.starts_with("warning:"), "{check:?}");
    }

    #[test]
    fn escalation_check_reports_an_unusable_notify_user() {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let own = unsafe { libc::geteuid() };
        let other = if own == 0 { 1 } else { 0 };
        let config = escalation_config(Some(&other.to_string()), true);
        let check = escalation_check(&config, &config.profiles["p"], own.max(1));
        assert!(!check.passed, "{check:?}");

        let config = escalation_config(Some(&own.max(1).to_string()), true);
        let check = escalation_check(&config, &config.profiles["p"], own.max(1));
        assert!(check.passed, "{check:?}");

        let config = escalation_config(None, true);
        let check = escalation_check(&config, &config.profiles["p"], own.max(1));
        assert!(check.passed, "{check:?}");
    }

    #[test]
    fn granted_rules_check_fails_for_a_disabled_store() {
        let path = Path::new("/state/granted-rules/p.toml");
        let ok = granted_rules_check(Some(&ProfileGrants::Enabled(Vec::new())), path);
        assert!(ok.passed);
        let disabled = granted_rules_check(
            Some(&ProfileGrants::Disabled("mode 0644".to_string())),
            path,
        );
        assert!(!disabled.passed);
        assert!(disabled.message.contains("mode 0644"), "{disabled:?}");
        assert!(!granted_rules_check(None, path).passed);
    }
}
