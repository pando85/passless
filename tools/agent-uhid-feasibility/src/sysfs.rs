use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SysfsDevice {
    pub sysfs_path: PathBuf,
    pub name: String,
    pub phys: String,
    pub uniq: String,
    pub vendor: String,
    pub product: String,
    pub hidraw_nodes: Vec<PathBuf>,
}

pub fn find_hid_devices() -> Result<Vec<PathBuf>, String> {
    let hid_path = Path::new("/sys/bus/hid/devices");
    if !hid_path.exists() {
        return Err("/sys/bus/hid/devices not found".to_string());
    }

    let entries =
        fs::read_dir(hid_path).map_err(|e| format!("Failed to read hid devices: {}", e))?;

    let mut devices = Vec::new();
    for entry in entries.flatten() {
        devices.push(entry.path());
    }

    Ok(devices)
}

fn parse_uevent(device_path: &Path) -> (String, String, String) {
    let uevent_path = device_path.join("uevent");
    let mut name = String::new();
    let mut phys = String::new();
    let mut uniq = String::new();

    if let Ok(contents) = fs::read_to_string(&uevent_path) {
        for line in contents.lines() {
            if let Some(val) = line.strip_prefix("HID_NAME=") {
                name = val.to_string();
            } else if let Some(val) = line.strip_prefix("HID_PHYS=") {
                phys = val.to_string();
            } else if let Some(val) = line.strip_prefix("HID_UNIQ=") {
                uniq = val.to_string();
            }
        }
    }

    (name, phys, uniq)
}

fn parse_device_dir_name(dir_name: &str) -> (String, String) {
    let parts: Vec<&str> = dir_name.split(':').collect();
    if parts.len() >= 3 {
        let vendor = parts[1].to_string();
        let product_rest: Vec<&str> = parts[2].split('.').collect();
        let product = product_rest[0].to_string();
        (vendor, product)
    } else {
        (String::new(), String::new())
    }
}

pub fn discover_device(sysfs_path: &Path) -> Result<SysfsDevice, String> {
    if !sysfs_path.exists() {
        return Err(format!("Path does not exist: {:?}", sysfs_path));
    }

    let (name, phys, uniq) = parse_uevent(sysfs_path);

    let dir_name = sysfs_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let (vendor, product) = parse_device_dir_name(&dir_name);

    let hidraw_nodes = find_hidraw_nodes(sysfs_path)?;

    Ok(SysfsDevice {
        sysfs_path: sysfs_path.to_path_buf(),
        name,
        phys,
        uniq,
        vendor,
        product,
        hidraw_nodes,
    })
}

pub fn find_hidraw_nodes(device_path: &Path) -> Result<Vec<PathBuf>, String> {
    find_hidraw_nodes_inner(device_path, 0)
}

fn find_hidraw_nodes_inner(device_path: &Path, depth: u32) -> Result<Vec<PathBuf>, String> {
    if depth > 5 {
        return Ok(Vec::new());
    }

    let mut nodes = Vec::new();

    for entry in
        fs::read_dir(device_path).map_err(|e| format!("Failed to read device dir: {}", e))?
    {
        let entry = entry.map_err(|e| format!("Failed to read dir entry: {}", e))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();

        if name.starts_with("hidraw") {
            let dev_path = Path::new("/dev").join(&name);
            if dev_path.exists() {
                nodes.push(dev_path);
            }
        }

        if path.is_dir()
            && path.read_link().is_err()
            && let Ok(sub_nodes) = find_hidraw_nodes_inner(&path, depth + 1)
        {
            nodes.extend(sub_nodes);
        }
    }

    nodes.sort();
    Ok(nodes)
}

pub fn find_device_by_uniq(target_uniq: &str) -> Result<Option<SysfsDevice>, String> {
    let devices = find_hid_devices()?;

    for dev_path in devices {
        let (_name, _phys, uniq) = parse_uevent(&dev_path);
        if uniq == target_uniq {
            return discover_device(&dev_path).map(Some);
        }
    }

    Ok(None)
}
