use std::path::Path;

use agent_uhid_feasibility::hidraw_map;
use agent_uhid_feasibility::lifecycle;
use agent_uhid_feasibility::perm_probe;
use agent_uhid_feasibility::sysfs;

#[test]
fn test_perm_probe_nonexistent_path() {
    let result = perm_probe::probe_path("/dev/nonexistent_uhid_probe_12345");
    assert!(!result.exists);
    assert!(!result.open_rw_ok);
    assert!(result.error.is_some());
}

#[test]
fn test_perm_probe_dev_uhid_exists_check() {
    let result = perm_probe::probe_path("/dev/uhid");
    if Path::new("/dev/uhid").exists() {
        assert!(result.exists);
    } else {
        assert!(!result.exists);
    }
}

#[test]
fn test_sysfs_hid_devices_dir_exists() {
    let result = sysfs::find_hid_devices();
    if Path::new("/sys/bus/hid/devices").exists() {
        assert!(result.is_ok());
    }
}

#[test]
fn test_discover_device_nonexistent_path() {
    let result = sysfs::discover_device(Path::new("/nonexistent/path"));
    assert!(result.is_err());
}

#[test]
fn test_find_device_by_uniq_nonexistent() {
    let result = sysfs::find_device_by_uniq("nonexistent-uniq-12345");
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn test_hidraw_map_resolve_nonexistent() {
    let result = hidraw_map::resolve_hidraw_by_uniq("nonexistent-uniq-12345");
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn test_check_uhid_kernel_module() {
    let loaded = perm_probe::check_uhid_kernel_module();
    if Path::new("/sys/module/uhid").exists() {
        assert!(loaded);
    }
}

#[test]
fn test_probe_environment_returns_struct() {
    let report = perm_probe::probe_environment();
    let _ = report.hidraw_count;
}

#[test]
fn test_cleanup_returns_vec() {
    let result = lifecycle::cleanup_all_probe_devices();
    assert!(result.is_ok());
}

#[test]
fn test_lifecycle_report_debug() {
    let report = lifecycle::LifecycleReport {
        device_id: "test".to_string(),
        create_ok: true,
        create_duration_ms: 100,
        destroy_ok: true,
        destroy_duration_ms: 50,
        error: None,
    };
    let debug = format!("{:?}", report);
    assert!(debug.contains("test"));
    assert!(debug.contains("100"));
}

#[test]
fn test_concurrent_cycle_results_debug() {
    let result = lifecycle::ConcurrentCycleResult {
        reports: vec![],
        total_duration_ms: 0,
        all_ok: true,
    };
    let debug = format!("{:?}", result);
    assert!(debug.contains("all_ok: true"));
}

#[test]
fn test_hidraw_mapping_debug() {
    let m = hidraw_map::HidrawMapping {
        sysfs_path: Path::new("/sys/test").to_path_buf(),
        hidraw_path: Path::new("/dev/hidraw0").to_path_buf(),
        name: "test".to_string(),
        uniq: "test-uniq".to_string(),
        vendor: "0x1234".to_string(),
        product: "0x5678".to_string(),
    };
    let debug = format!("{:?}", m);
    assert!(debug.contains("hidraw0"));
}

#[test]
fn test_perm_probe_result_debug() {
    let r = perm_probe::PermProbeResult {
        path: "/dev/test".to_string(),
        exists: true,
        readable: true,
        writable: false,
        open_rw_ok: false,
        mode: Some(0o660),
        owner_uid: Some(0),
        group_gid: Some(10),
        error: None,
    };
    let debug = format!("{:?}", r);
    assert!(debug.contains("/dev/test"));
}

#[test]
fn test_sysfs_device_debug() {
    let dev = sysfs::SysfsDevice {
        sysfs_path: Path::new("/sys/test").to_path_buf(),
        name: "test".to_string(),
        phys: "phys".to_string(),
        uniq: "uniq".to_string(),
        vendor: "0x1234".to_string(),
        product: "0x5678".to_string(),
        hidraw_nodes: vec![],
    };
    let debug = format!("{:?}", dev);
    assert!(debug.contains("test"));
}

#[test]
fn test_environment_report_debug() {
    let r = perm_probe::EnvironmentReport {
        uhid_module_loaded: false,
        uhid_dev_exists: false,
        uhid_rw_ok: false,
        hidraw_count: 0,
        hid_readable_count: 0,
        hid_writable_count: 0,
    };
    let debug = format!("{:?}", r);
    assert!(debug.contains("uhid_module_loaded: false"));
}
