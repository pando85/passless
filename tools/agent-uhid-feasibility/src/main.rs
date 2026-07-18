use std::env;
use std::process;

use agent_uhid_feasibility::hidraw_map;
use agent_uhid_feasibility::lifecycle;
use agent_uhid_feasibility::perm_probe;
use agent_uhid_feasibility::sysfs;

use passless_uhid::DeviceIdentity;

fn usage() {
    eprintln!(
        "Usage: uhid-feasibility <command> [args]

Commands:
  env                  Probe environment (UHID module, /dev/uhid, hidraw perms)
  discover             List HID devices via sysfs
  discover <uniq>      Find specific device by uniq
  hidraw-map           List all hidraw nodes with identity info
  hidraw-map <uniq>    Resolve hidraw path for a given uniq
  perm                 Probe /dev/uhid permissions
  perm <path>          Probe permissions on specific path
  create <name> <uniq> <vendor> <product> <version>
                       Create a UHID device with given identity
  cycle <count>        Run rapid create-destroy cycles
  concurrent <count>   Run concurrent create-destroy cycles
  cleanup              List probe devices still present in sysfs
  help                 Show this help
"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        usage();
        process::exit(1);
    }

    let result = match args[1].as_str() {
        "env" => cmd_env(),
        "discover" => cmd_discover(&args[2..]),
        "hidraw-map" => cmd_hidraw_map(&args[2..]),
        "perm" => cmd_perm(&args[2..]),
        "create" => cmd_create(&args[2..]),
        "cycle" => cmd_cycle(&args[2..]),
        "concurrent" => cmd_concurrent(&args[2..]),
        "cleanup" => cmd_cleanup(),
        "help" | "--help" | "-h" => {
            usage();
            Ok(())
        }
        other => {
            eprintln!("Unknown command: {}", other);
            usage();
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn cmd_env() -> Result<(), String> {
    let report = perm_probe::probe_environment();
    println!("=== Environment Probe ===");
    println!("UHID kernel module loaded: {}", report.uhid_module_loaded);
    println!("/dev/uhid exists:           {}", report.uhid_dev_exists);
    println!("/dev/uhid R/W open OK:      {}", report.uhid_rw_ok);
    println!("hidraw device count:        {}", report.hidraw_count);
    println!("hidraw readable count:      {}", report.hid_readable_count);
    println!("hidraw writable count:      {}", report.hid_writable_count);
    println!();

    let uhid_perm = perm_probe::probe_uhid_permissions();
    println!("=== /dev/uhid Permissions ===");
    println!("  exists:    {}", uhid_perm.exists);
    if uhid_perm.exists {
        println!("  mode:      {:o}", uhid_perm.mode.unwrap_or(0));
        if let Some(uid) = uhid_perm.owner_uid {
            println!("  owner uid: {}", uid);
        }
        if let Some(gid) = uhid_perm.group_gid {
            println!("  group gid: {}", gid);
        }
        println!("  readable:  {}", uhid_perm.readable);
        println!("  writable:  {}", uhid_perm.writable);
        println!("  open R/W:  {}", uhid_perm.open_rw_ok);
    }

    Ok(())
}

fn cmd_discover(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        let devices = sysfs::find_hid_devices()?;
        println!("=== HID Devices (sysfs) ===");
        println!("Count: {}", devices.len());
        for dev_path in &devices {
            let dev = sysfs::discover_device(dev_path)?;
            println!();
            println!("  sysfs:  {:?}", dev.sysfs_path);
            println!("  name:   {}", dev.name);
            println!("  phys:   {}", dev.phys);
            println!("  uniq:   {}", dev.uniq);
            println!("  vendor: {}", dev.vendor);
            println!("  product:{}", dev.product);
            println!("  hidraw: {:?}", dev.hidraw_nodes);
        }
    } else {
        let uniq = &args[0];
        match sysfs::find_device_by_uniq(uniq)? {
            Some(dev) => {
                println!("Found device with uniq '{}':", uniq);
                println!("  sysfs:  {:?}", dev.sysfs_path);
                println!("  name:   {}", dev.name);
                println!("  phys:   {}", dev.phys);
                println!("  vendor: {}", dev.vendor);
                println!("  product:{}", dev.product);
                println!("  hidraw: {:?}", dev.hidraw_nodes);
            }
            None => {
                println!("No device found with uniq '{}'", uniq);
            }
        }
    }

    Ok(())
}

fn cmd_hidraw_map(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        let mappings = hidraw_map::list_all_hidraw_nodes()?;
        println!("=== Hidraw Mappings ===");
        println!("Count: {}", mappings.len());
        for m in &mappings {
            println!();
            println!("  hidraw: {:?}", m.hidraw_path);
            println!("  sysfs:  {:?}", m.sysfs_path);
            println!("  name:   {}", m.name);
            println!("  uniq:   {}", m.uniq);
            println!("  vendor: {}", m.vendor);
            println!("  product:{}", m.product);
        }
    } else {
        let uniq = &args[0];
        match hidraw_map::resolve_hidraw_by_uniq(uniq)? {
            Some(m) => {
                println!("hidraw for uniq '{}': {:?}", uniq, m.hidraw_path);
            }
            None => {
                println!("No hidraw mapping found for uniq '{}'", uniq);
            }
        }
    }

    Ok(())
}

fn cmd_perm(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        let result = perm_probe::probe_uhid_permissions();
        print_perm_result(&result);
    } else {
        let result = perm_probe::probe_path(&args[0]);
        print_perm_result(&result);
    }

    Ok(())
}

fn print_perm_result(r: &perm_probe::PermProbeResult) {
    println!("=== Permission Probe: {} ===", r.path);
    println!("  exists:    {}", r.exists);
    if r.exists {
        println!("  mode:      {:o}", r.mode.unwrap_or(0));
        if let Some(uid) = r.owner_uid {
            println!("  owner uid: {}", uid);
        }
        if let Some(gid) = r.group_gid {
            println!("  group gid: {}", gid);
        }
        println!("  readable:  {}", r.readable);
        println!("  writable:  {}", r.writable);
        println!("  open R/W:  {}", r.open_rw_ok);
    }
    if let Some(ref e) = r.error {
        println!("  error:     {}", e);
    }
}

fn cmd_create(args: &[String]) -> Result<(), String> {
    if args.len() < 5 {
        return Err("Usage: create <name> <uniq> <vendor_hex> <product_hex> <version_hex>".into());
    }

    let name = args[0].clone();
    let uniq = args[1].clone();
    let vendor = u32::from_str_radix(args[2].trim_start_matches("0x"), 16)
        .map_err(|e| format!("Invalid vendor: {}", e))?;
    let product = u32::from_str_radix(args[3].trim_start_matches("0x"), 16)
        .map_err(|e| format!("Invalid product: {}", e))?;
    let version = u32::from_str_radix(args[4].trim_start_matches("0x"), 16)
        .map_err(|e| format!("Invalid version: {}", e))?;

    let identity = DeviceIdentity {
        name,
        phys: format!("{}-phys", uniq),
        uniq,
        vendor,
        product,
        version,
    };

    println!("Creating UHID device: {:?}", identity);
    let mut device = passless_uhid::RawUhidDevice::create(identity).map_err(|e| e.to_string())?;
    println!(
        "Device created successfully. started={}",
        device.is_started()
    );
    println!("Press Enter to destroy...");
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    device.destroy().map_err(|e| e.to_string())?;
    println!("Device destroyed.");

    Ok(())
}

fn cmd_cycle(args: &[String]) -> Result<(), String> {
    let count: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(5);

    println!("Running {} rapid create-destroy cycles...", count);
    let base = DeviceIdentity {
        name: "feasibility-cycle".to_string(),
        phys: "feasibility-cycle-0-phys".to_string(),
        uniq: "feasibility-cycle-0".to_string(),
        vendor: 0x15d9,
        product: 0xF1D0,
        version: 0x0001,
    };

    let reports = lifecycle::rapid_cycle_test(count, base);
    let mut ok_count = 0;
    for (i, r) in reports.iter().enumerate() {
        let status = if r.create_ok && r.destroy_ok {
            ok_count += 1;
            "OK"
        } else {
            "FAIL"
        };
        println!(
            "  [{}] {} create={}ms destroy={}ms err={:?}",
            i, status, r.create_duration_ms, r.destroy_duration_ms, r.error
        );
    }
    println!("{}/{} cycles succeeded", ok_count, count);

    Ok(())
}

fn cmd_concurrent(args: &[String]) -> Result<(), String> {
    let count: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(3);

    println!("Running {} concurrent create-destroy cycles...", count);

    let identities: Vec<DeviceIdentity> = (0..count)
        .map(|i| DeviceIdentity {
            name: format!("feasibility-concurrent-{}", i),
            phys: format!("feasibility-concurrent-{}-phys", i),
            uniq: format!("feasibility-concurrent-{}", i),
            vendor: 0x15d9,
            product: 0xF1D0,
            version: 0x0001,
        })
        .collect();

    let result = lifecycle::run_concurrent_cycles(identities, 50);

    for r in &result.reports {
        let status = if r.create_ok && r.destroy_ok {
            "OK"
        } else {
            "FAIL"
        };
        println!(
            "  [{}] {} create={}ms destroy={}ms err={:?}",
            r.device_id, status, r.create_duration_ms, r.destroy_duration_ms, r.error
        );
    }
    println!(
        "Total: {}ms, all_ok={}",
        result.total_duration_ms, result.all_ok
    );

    Ok(())
}

fn cmd_cleanup() -> Result<(), String> {
    let cleaned = lifecycle::cleanup_all_probe_devices()?;
    println!("=== Cleanup Scan ===");
    if cleaned.is_empty() {
        println!("No probe devices found in sysfs.");
    } else {
        println!("Found {} probe device(s):", cleaned.len());
        for c in &cleaned {
            println!("  {}", c);
        }
    }

    Ok(())
}
