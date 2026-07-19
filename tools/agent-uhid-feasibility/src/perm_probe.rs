use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PermProbeResult {
    pub path: String,
    pub exists: bool,
    pub readable: bool,
    pub writable: bool,
    pub open_rw_ok: bool,
    pub mode: Option<u32>,
    pub owner_uid: Option<u32>,
    pub group_gid: Option<u32>,
    pub error: Option<String>,
}

pub fn probe_uhid_permissions() -> PermProbeResult {
    probe_path("/dev/uhid")
}

pub fn probe_path(path: &str) -> PermProbeResult {
    let p = Path::new(path);
    let exists = p.exists();

    if !exists {
        return PermProbeResult {
            path: path.to_string(),
            exists: false,
            readable: false,
            writable: false,
            open_rw_ok: false,
            mode: None,
            owner_uid: None,
            group_gid: None,
            error: Some("Path does not exist".to_string()),
        };
    }

    let metadata = match fs::metadata(p) {
        Ok(m) => m,
        Err(e) => {
            return PermProbeResult {
                path: path.to_string(),
                exists: true,
                readable: false,
                writable: false,
                open_rw_ok: false,
                mode: None,
                owner_uid: None,
                group_gid: None,
                error: Some(format!("Failed to stat: {}", e)),
            };
        }
    };

    let mode = Some(metadata.permissions().mode() & 0o7777);

    #[cfg(target_os = "linux")]
    let (owner_uid, group_gid) = {
        use std::os::linux::fs::MetadataExt;
        (Some(metadata.st_uid()), Some(metadata.st_gid()))
    };

    #[cfg(not(target_os = "linux"))]
    let (owner_uid, group_gid) = (None, None);

    let readable = metadata.permissions().mode() & 0o444 != 0;
    let writable = metadata.permissions().mode() & 0o222 != 0;

    let open_rw_ok = OpenOptions::new().read(true).write(true).open(p).is_ok();

    PermProbeResult {
        path: path.to_string(),
        exists: true,
        readable,
        writable,
        open_rw_ok,
        mode,
        owner_uid,
        group_gid,
        error: None,
    }
}

pub fn probe_all_hidraw_permissions() -> Vec<PermProbeResult> {
    let mut results = Vec::new();

    if let Ok(entries) = fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("hidraw") {
                results.push(probe_path(&entry.path().to_string_lossy()));
            }
        }
    }

    results
}

pub fn check_uhid_kernel_module() -> bool {
    Path::new("/sys/module/uhid").exists()
}

pub fn check_uhid_loaded_via_modules() -> bool {
    if let Ok(contents) = fs::read_to_string("/proc/modules") {
        contents.lines().any(|line| line.starts_with("uhid "))
    } else {
        false
    }
}

#[derive(Debug, Clone)]
pub struct EnvironmentReport {
    pub uhid_module_loaded: bool,
    pub uhid_dev_exists: bool,
    pub uhid_rw_ok: bool,
    pub hidraw_count: usize,
    pub hid_readable_count: usize,
    pub hid_writable_count: usize,
}

pub fn probe_environment() -> EnvironmentReport {
    let uhid_module = check_uhid_kernel_module() || check_uhid_loaded_via_modules();
    let uhid_dev = Path::new("/dev/uhid").exists();
    let uhid_rw = if uhid_dev {
        probe_uhid_permissions().open_rw_ok
    } else {
        false
    };

    let hidraw_probes = probe_all_hidraw_permissions();
    let hidraw_count = hidraw_probes.len();
    let hid_readable_count = hidraw_probes.iter().filter(|p| p.readable).count();
    let hid_writable_count = hidraw_probes.iter().filter(|p| p.writable).count();

    EnvironmentReport {
        uhid_module_loaded: uhid_module,
        uhid_dev_exists: uhid_dev,
        uhid_rw_ok: uhid_rw,
        hidraw_count,
        hid_readable_count,
        hid_writable_count,
    }
}
