use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use passless_uhid::{DeviceIdentity, RawUhidDevice};

#[derive(Debug, Clone)]
pub struct LifecycleReport {
    pub device_id: String,
    pub create_ok: bool,
    pub create_duration_ms: u64,
    pub destroy_ok: bool,
    pub destroy_duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct ConcurrentCycleResult {
    pub reports: Vec<LifecycleReport>,
    pub total_duration_ms: u64,
    pub all_ok: bool,
}

pub fn create_destroy_cycle(identity: DeviceIdentity) -> LifecycleReport {
    let device_id = identity.uniq.clone();
    let start = Instant::now();

    let create_result = RawUhidDevice::create(identity);
    let create_duration = start.elapsed().as_millis() as u64;

    match create_result {
        Ok(mut device) => {
            let destroy_start = Instant::now();
            let destroy_ok = device.destroy().is_ok();
            let destroy_duration = destroy_start.elapsed().as_millis() as u64;

            LifecycleReport {
                device_id,
                create_ok: true,
                create_duration_ms: create_duration,
                destroy_ok,
                destroy_duration_ms: destroy_duration,
                error: None,
            }
        }
        Err(e) => LifecycleReport {
            device_id,
            create_ok: false,
            create_duration_ms: create_duration,
            destroy_ok: false,
            destroy_duration_ms: 0,
            error: Some(e.to_string()),
        },
    }
}

pub fn run_concurrent_cycles(
    identities: Vec<DeviceIdentity>,
    stagger_ms: u64,
) -> ConcurrentCycleResult {
    let reports: Arc<Mutex<Vec<LifecycleReport>>> = Arc::new(Mutex::new(Vec::new()));
    let total_start = Instant::now();

    let handles: Vec<_> = identities
        .into_iter()
        .enumerate()
        .map(|(i, identity)| {
            let reports = Arc::clone(&reports);
            thread::spawn(move || {
                if stagger_ms > 0 {
                    thread::sleep(Duration::from_millis(stagger_ms * i as u64));
                }
                let report = create_destroy_cycle(identity);
                reports.lock().unwrap().push(report);
            })
        })
        .collect();

    for handle in handles {
        let _ = handle.join();
    }

    let total_duration = total_start.elapsed().as_millis() as u64;
    let final_reports = reports.lock().unwrap().clone();
    let all_ok = final_reports.iter().all(|r| r.create_ok && r.destroy_ok);

    ConcurrentCycleResult {
        reports: final_reports,
        total_duration_ms: total_duration,
        all_ok,
    }
}

pub fn cleanup_all_probe_devices() -> Result<Vec<String>, String> {
    let devices = crate::sysfs::find_hid_devices()?;
    let mut cleaned = Vec::new();

    for dev_path in devices {
        if let Ok(dev) = crate::sysfs::discover_device(&dev_path)
            && (dev.name.contains("feasibility-probe")
                || dev.name.contains("feasibility-cycle")
                || dev.name.contains("feasibility-concurrent")
                || dev.name.contains("agent-uhid"))
        {
            cleaned.push(format!("{:?} (name={})", dev_path, dev.name));
        }
    }

    Ok(cleaned)
}

pub fn rapid_cycle_test(count: usize, base_identity: DeviceIdentity) -> Vec<LifecycleReport> {
    let mut reports = Vec::new();

    for i in 0..count {
        let mut identity = base_identity.clone();
        identity.uniq = format!("{}-{}", base_identity.uniq, i);
        identity.name = format!("{}-{}", base_identity.name, i);
        identity.phys = format!("{}-phys", identity.uniq);

        let report = create_destroy_cycle(identity);
        reports.push(report);
    }

    reports
}
