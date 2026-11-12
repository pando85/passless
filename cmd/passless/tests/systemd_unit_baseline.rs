//! The system unit's hardening baseline (ADR 0014 section 13) and its state directory (section
//! 8.4), checked against the shipped files so that a drifting unit fails a test, not an audit.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn contrib(file: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contrib")
        .join(file);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The `[Service]` directives of a unit: comments dropped, repeated keys joined by a space.
fn service_directives(unit: &str) -> BTreeMap<String, String> {
    let mut in_service = false;
    let mut directives: BTreeMap<String, String> = BTreeMap::new();
    for line in unit.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_service = section == "Service";
            continue;
        }
        if let (true, Some((key, value))) = (in_service, line.split_once('=')) {
            let slot = directives.entry(key.trim().to_string()).or_default();
            if !slot.is_empty() {
                slot.push(' ');
            }
            slot.push_str(value.trim());
        }
    }
    directives
}

fn agent_unit() -> BTreeMap<String, String> {
    service_directives(&contrib("systemd/passless-agent.service"))
}

fn is_enabled(value: &str) -> bool {
    matches!(value, "true" | "yes" | "on" | "1")
}

#[test]
fn the_unit_enables_every_baseline_directive_of_the_adr() {
    let unit = agent_unit();
    for directive in [
        "ProtectHostname",
        "ProtectClock",
        "ProtectKernelLogs",
        "LockPersonality",
        "RestrictRealtime",
        "ProtectKernelTunables",
        "ProtectControlGroups",
        "ProtectKernelModules",
        "RestrictSUIDSGID",
    ] {
        let value = unit
            .get(directive)
            .unwrap_or_else(|| panic!("{directive} is missing from the unit"));
        assert!(is_enabled(value), "{directive}={value}");
    }
}

#[test]
fn the_unit_keeps_the_root_launch_model_the_baseline_is_designed_around() {
    let unit = agent_unit();
    // `NoNewPrivileges=false` is required: the daemon setuids to the principal and browser users.
    assert_eq!(
        unit.get("NoNewPrivileges").map(String::as_str),
        Some("false")
    );
    // The daemon runs as root; the unit must not drop to a User= or Group=.
    assert!(
        !unit.contains_key("User") && !unit.contains_key("Group"),
        "{unit:?}"
    );
    // The filesystem is read-only apart from the named paths.
    assert_eq!(
        unit.get("ProtectSystem").map(String::as_str),
        Some("strict")
    );
    // The directives the ADR lists as still to evaluate are not silently half-enabled.
    assert_eq!(
        unit.get("PrivateDevices").map(String::as_str),
        Some("false")
    );
    for deferred in [
        "SystemCallFilter",
        "CapabilityBoundingSet",
        "RestrictNamespaces",
        "MemoryDenyWriteExecute",
    ] {
        assert!(
            !unit.contains_key(deferred),
            "{deferred} is documented as deferred (ADR 0014 section 13); amend the ADR with it"
        );
    }
}

#[test]
fn the_state_directory_is_systemd_managed_and_matches_the_tmpfiles_entry() {
    let unit = agent_unit();
    assert_eq!(
        unit.get("StateDirectory").map(String::as_str),
        Some("passless-agent"),
        "ADR 0014 section 8.4: the system unit's state directory is `StateDirectory=`"
    );
    // The granted-rules store needs 0700; systemd's default for StateDirectory is 0755.
    assert_eq!(
        unit.get("StateDirectoryMode").map(String::as_str),
        Some("0700")
    );
    let tmpfiles = contrib("tmpfiles/passless-agent.conf");
    let entry = tmpfiles
        .lines()
        .map(str::trim)
        .find(|line| line.split_whitespace().nth(1) == Some("/var/lib/passless-agent"))
        .expect("tmpfiles creates /var/lib/passless-agent");
    let fields: Vec<&str> = entry.split_whitespace().collect();
    assert_eq!(fields[0], "d");
    assert_eq!(&fields[2..5], ["0700", "root", "root"], "{entry}");
}
