use std::path::PathBuf;

use crate::sysfs;

#[derive(Debug, Clone)]
pub struct HidrawMapping {
    pub sysfs_path: PathBuf,
    pub hidraw_path: PathBuf,
    pub name: String,
    pub uniq: String,
    pub vendor: String,
    pub product: String,
}

pub fn resolve_hidraw_by_uniq(target_uniq: &str) -> Result<Option<HidrawMapping>, String> {
    let dev = sysfs::find_device_by_uniq(target_uniq)?;
    match dev {
        Some(sysfs_dev) => {
            if let Some(hidraw) = sysfs_dev.hidraw_nodes.first() {
                Ok(Some(HidrawMapping {
                    sysfs_path: sysfs_dev.sysfs_path,
                    hidraw_path: hidraw.clone(),
                    name: sysfs_dev.name,
                    uniq: sysfs_dev.uniq,
                    vendor: sysfs_dev.vendor,
                    product: sysfs_dev.product,
                }))
            } else {
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

pub fn list_all_hidraw_nodes() -> Result<Vec<HidrawMapping>, String> {
    let devices = sysfs::find_hid_devices()?;
    let mut mappings = Vec::new();

    for dev_path in devices {
        if let Ok(dev) = sysfs::discover_device(&dev_path) {
            for hidraw in &dev.hidraw_nodes {
                mappings.push(HidrawMapping {
                    sysfs_path: dev.sysfs_path.clone(),
                    hidraw_path: hidraw.clone(),
                    name: dev.name.clone(),
                    uniq: dev.uniq.clone(),
                    vendor: dev.vendor.clone(),
                    product: dev.product.clone(),
                });
            }
        }
    }

    Ok(mappings)
}
