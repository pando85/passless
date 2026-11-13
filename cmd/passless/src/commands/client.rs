//! FIDO2 Client Management Commands

use crate::authenticator::{CMD_PASSLESS_RESET_UV_RETRIES, RESET_UV_RETRIES_SUBCOMMAND};
use crate::credential_backup::{
    BACKUP_COMMIT_SUBCOMMAND, BACKUP_PREPARE_SUBCOMMAND, CMD_PASSLESS_BACKUP, CMD_PASSLESS_RESTORE,
    MAX_BACKUP_BUNDLE_SIZE, PASSLESS_AAGUID, backup_commit_auth_data, backup_prepare_auth_data,
    restore_auth_data,
};
use crate::credential_protection::{
    CMD_PASSLESS_SET_CRED_PROTECT, CredProtectChange, MAX_CRED_PROTECT_LEVEL,
    MIN_CRED_PROTECT_LEVEL, effective_level, encode_request, level_name, parse_response,
    set_cred_protect_auth_data,
};

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use passless_core::{OutputFormat, Result};

use rpassword::read_password;

use zeroize::Zeroizing;

use serde::Serialize;

use soft_fido2::request::{
    CredentialManagementRequest, DeleteCredentialRequest, EnumerateCredentialsRequest,
    UpdateUserRequest,
};
use soft_fido2::{Client, PinProtocol, Transport, TransportList};

/// Device information for enumeration
#[derive(Debug, Clone)]
struct DeviceInfo {
    index: usize,
    name: String,
    aaguid_hex: String,
    versions: String,
}

/// JSON output structure for credential listing
#[derive(Serialize)]
struct ListOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<String>,
    total_rps: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    filtered_rps: Option<usize>,
    total_credentials: usize,
    relying_parties: Vec<RpOutput>,
}

/// Relying party information in JSON output
#[derive(Serialize)]
struct RpOutput {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(serialize_with = "serialize_hex")]
    rp_id_hash: Vec<u8>,
    credentials: Vec<CredentialOutput>,
}

/// Credential information in JSON output
#[derive(Serialize)]
struct CredentialOutput {
    #[serde(serialize_with = "serialize_hex")]
    user_id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(serialize_with = "serialize_hex")]
    credential_id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cred_protect: Option<u8>,
}

/// Serialize byte vectors as hex strings in JSON output
fn serialize_hex<S>(data: &Vec<u8>, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(data))
}

/// Convert AAGUID hex string to human-readable device name
fn aaguid_hex_to_name(aaguid_hex: &str) -> String {
    if let Ok(bytes) = hex::decode(aaguid_hex)
        && let Ok(s) = String::from_utf8(bytes)
        && s.chars()
            .all(|c| c.is_ascii_graphic() || c == '.' || c == '-')
    {
        return s;
    }
    "FIDO2 Authenticator".to_string()
}

/// Query authenticator information via getInfo command
fn query_device_info(transport: &mut Transport) -> (String, String) {
    match Client::authenticator_get_info(transport) {
        Ok(response) => {
            if let Ok(info_value) =
                soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&response)
                && let Ok(info) = parse_authenticator_info(&info_value)
            {
                let aaguid_hex = info
                    .aaguid
                    .as_ref()
                    .map(hex::encode)
                    .unwrap_or_else(|| "unknown".to_string());
                let versions = info
                    .versions
                    .unwrap_or_else(|| vec!["FIDO2".to_string()])
                    .join(", ");
                return (aaguid_hex, versions);
            }
            ("unknown".to_string(), "FIDO2".to_string())
        }
        Err(_) => ("unknown".to_string(), "FIDO2".to_string()),
    }
}

/// Collect information about all available devices
fn enumerate_device_info(list: &TransportList) -> Vec<DeviceInfo> {
    (0..list.len())
        .filter_map(|i| {
            let mut transport = list.get(i)?;

            let (aaguid_hex, versions) = if transport.open().is_ok() {
                let info = query_device_info(&mut transport);
                transport.close();
                info
            } else {
                ("unavailable".to_string(), "FIDO2".to_string())
            };

            let name = aaguid_hex_to_name(&aaguid_hex);

            Some(DeviceInfo {
                index: i,
                name,
                aaguid_hex,
                versions,
            })
        })
        .collect()
}

/// Format device list for error messages
fn format_device_list(devices: &[DeviceInfo]) -> String {
    devices
        .iter()
        .map(|d| format!("  [{}] {} (AAGUID: {})", d.index, d.name, d.aaguid_hex))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Try to open a device by numeric index
fn open_device_by_index(list: &TransportList, idx: usize) -> Result<Transport> {
    if idx >= list.len() {
        return Err(passless_core::Error::Other(format!(
            "Device index {} out of range. {} device(s) available (0-{})",
            idx,
            list.len(),
            list.len() - 1
        )));
    }

    let mut transport = list.get(idx).ok_or_else(|| {
        passless_core::Error::Other(format!("Failed to get device at index {}", idx))
    })?;

    transport.open().map_err(|e| {
        passless_core::Error::Other(format!("Failed to open device {}: {:?}", idx, e))
    })?;

    Ok(transport)
}

/// Try to open a device by name or AAGUID substring match
fn open_device_by_selector(list: &TransportList, selector: &str) -> Result<Transport> {
    let sel_lower = selector.to_lowercase();
    let mut matches: Vec<(DeviceInfo, Transport)> = Vec::new();
    let mut non_matches: Vec<DeviceInfo> = Vec::new();

    for i in 0..list.len() {
        let Some(mut transport) = list.get(i) else {
            continue;
        };

        let (aaguid_hex, versions) = if transport.open().is_ok() {
            query_device_info(&mut transport)
        } else {
            non_matches.push(DeviceInfo {
                index: i,
                name: "Unavailable".to_string(),
                aaguid_hex: "unavailable".to_string(),
                versions: "FIDO2".to_string(),
            });
            continue;
        };

        let name = aaguid_hex_to_name(&aaguid_hex);
        let device_info = DeviceInfo {
            index: i,
            name,
            aaguid_hex,
            versions,
        };

        let is_match = device_info.name.to_lowercase().contains(&sel_lower)
            || device_info.aaguid_hex.to_lowercase().contains(&sel_lower);

        if is_match {
            matches.push((device_info, transport));
        } else {
            transport.close();
            non_matches.push(device_info);
        }
    }

    match matches.len() {
        0 => {
            let all_devices: Vec<DeviceInfo> = non_matches
                .into_iter()
                .chain(matches.into_iter().map(|(d, _)| d))
                .collect();
            Err(passless_core::Error::Other(format!(
                "No device found matching '{}'\n\n\
                 Available devices:\n{}\n\n\
                 Use 'passless client devices' to list all devices.",
                selector,
                format_device_list(&all_devices)
            )))
        }
        1 => {
            let (_device_info, transport) = matches.into_iter().next().ok_or_else(|| {
                passless_core::Error::Other("No device found after filtering".to_string())
            })?;
            Ok(transport)
        }
        _ => {
            let matched_devices: Vec<DeviceInfo> = matches
                .into_iter()
                .map(|(d, mut t)| {
                    t.close();
                    d
                })
                .collect();

            Err(passless_core::Error::Other(format!(
                "Ambiguous device selector '{}' matches {} devices:\n{}\n\n\
                 Please use a more specific selector or numeric index.",
                selector,
                matched_devices.len(),
                format_device_list(&matched_devices)
            )))
        }
    }
}

/// Try to open the first available device (prefers newest/highest index)
fn open_default_device(list: &TransportList) -> Result<Transport> {
    let mut last_error = None;

    for i in (0..list.len()).rev() {
        if let Some(mut transport) = list.get(i) {
            match transport.open() {
                Ok(_) => return Ok(transport),
                Err(e) => {
                    last_error = Some(format!("Device {} failed to open: {:?}", i, e));
                }
            }
        }
    }

    Err(passless_core::Error::Other(format!(
        "No accessible FIDO2 authenticators found.\n\
         Found {} device(s) but none could be opened.\n\n\
         Try specifying a device explicitly: --device <INDEX>\n\
         List available devices: passless client devices\n\n\
         Last error: {}",
        list.len(),
        last_error.unwrap_or_else(|| "No devices could be opened".to_string())
    )))
}

/// Open a FIDO2 authenticator by index, name, or AAGUID selector
fn open_authenticator(selector: Option<&str>) -> Result<Transport> {
    let list = TransportList::enumerate().map_err(|e| {
        passless_core::Error::Other(format!("Failed to enumerate authenticators: {:?}", e))
    })?;

    if list.is_empty() {
        return Err(passless_core::Error::Other(
            "No FIDO2 authenticators found.".to_string(),
        ));
    }

    match selector {
        None => open_default_device(&list),
        Some(sel) => {
            if let Ok(idx) = sel.parse::<usize>() {
                open_device_by_index(&list, idx)
            } else {
                open_device_by_selector(&list, sel)
            }
        }
    }
}

/// Authenticate for credential management operations
///
/// Tries the following authentication methods in order:
/// 1. UV token (built-in user verification)
/// 2. PIN token (if PIN is set on the authenticator)
///
/// Returns an error if neither method is available/supported.
fn authenticate_for_credential_management(
    transport: &mut Transport,
    output: OutputFormat,
) -> Result<soft_fido2::request::PinUvAuth> {
    authenticate_for_credential_management_cached(transport, output, &mut None)
}

/// A PIN typed by the user, kept in memory for the duration of one command so that a command
/// that needs two tokens (list, then change) asks for it once.
type PinCache = Option<Zeroizing<String>>;

/// Like [`authenticate_for_credential_management`], reusing and filling `pin_cache`.
fn authenticate_for_credential_management_cached(
    transport: &mut Transport,
    output: OutputFormat,
    pin_cache: &mut PinCache,
) -> Result<soft_fido2::request::PinUvAuth> {
    if output == OutputFormat::Plain {
        println!("Attempting user verification...");
    }

    match Client::get_uv_token_for_credential_management(transport, PinProtocol::V2) {
        Ok(token) => {
            if output == OutputFormat::Plain {
                println!("User verification successful\n");
            }
            Ok(token)
        }
        Err(uv_error) => {
            if output == OutputFormat::Plain {
                if is_uv_blocked_error(&uv_error) {
                    println!("  {}", format_uv_blocked_message(&uv_error));
                } else {
                    println!("  UV not available: {:?}", uv_error);
                }
            }

            fallback_to_pin_auth(transport, output, uv_error, pin_cache)
        }
    }
}

/// Try to authenticate for credential management, returning None on failure
///
/// This is used by operations that may proceed without authentication
/// (e.g., with passless authenticator that allows internal operations).
fn authenticate_for_credential_management_opt(
    transport: &mut Transport,
    output: OutputFormat,
) -> Option<soft_fido2::request::PinUvAuth> {
    match authenticate_for_credential_management(transport, output) {
        Ok(auth) => Some(auth),
        Err(_) => {
            if output == OutputFormat::Plain {
                println!("Proceeding without explicit authentication...\n");
            }
            None
        }
    }
}

/// Check if a soft_fido2 error represents a UV-blocked condition
fn is_uv_blocked_error(error: &soft_fido2::Error) -> bool {
    match error {
        soft_fido2::Error::CtapError(code) => *code == soft_fido2::StatusCode::UvBlocked as u8,
        _ => false,
    }
}

/// Format a UV-blocked error with actionable remediation
fn format_uv_blocked_message(error: &soft_fido2::Error) -> String {
    format!(
        "Built-in user verification (UV) is blocked: {:?}\n\
         UV retries have been exhausted.\n\
         Run `passless client pin uv-reset` to restore UV retries.",
        error
    )
}

/// Fallback to PIN authentication when UV fails
fn fallback_to_pin_auth(
    transport: &mut Transport,
    output: OutputFormat,
    uv_error: soft_fido2::Error,
    pin_cache: &mut PinCache,
) -> Result<soft_fido2::request::PinUvAuth> {
    if output == OutputFormat::Plain {
        println!("  Checking if PIN authentication is available...");
    }

    let info_response = Client::authenticator_get_info(transport).map_err(|e| {
        passless_core::Error::Other(format!("Failed to get authenticator info: {:?}", e))
    })?;

    let info_value: soft_fido2_ctap::cbor::Value = soft_fido2_ctap::cbor::decode(&info_response)
        .map_err(|e| {
            passless_core::Error::Other(format!("Failed to decode info response: {:?}", e))
        })?;

    let info = parse_authenticator_info(&info_value)?;

    let has_cred_mgmt = info
        .options
        .as_ref()
        .and_then(|opts| opts.get("credMgmt").or(opts.get("credentialMgmtPreview")))
        .copied()
        .unwrap_or(false);

    if !has_cred_mgmt {
        return Err(passless_core::Error::Other(
            "This authenticator does not support credential management".to_string(),
        ));
    }

    let client_pin_option = info
        .options
        .as_ref()
        .and_then(|opts| opts.get("clientPin"))
        .copied();

    match client_pin_option {
        Some(true) => {
            if output == OutputFormat::Plain {
                println!("  PIN is set on this authenticator");
                println!("  Falling back to PIN authentication...\n");
            }

            let pin = match pin_cache.clone() {
                Some(pin) => pin,
                None => {
                    if output == OutputFormat::Plain {
                        println!("Enter PIN: ");
                    }

                    let pin = Zeroizing::new(read_password().map_err(|e| {
                        passless_core::Error::Other(format!("Failed to read PIN: {:?}", e))
                    })?);

                    if pin.is_empty() {
                        return Err(passless_core::Error::Other(
                            "PIN is required for credential management on this authenticator"
                                .to_string(),
                        ));
                    }

                    if output == OutputFormat::Plain {
                        println!();
                    }
                    pin
                }
            };

            let token =
                Client::get_pin_token_for_credential_management(transport, &pin, PinProtocol::V2)
                    .map_err(|e| {
                    // A rejected PIN must not be offered again.
                    *pin_cache = None;
                    passless_core::Error::Other(format!(
                        "PIN authentication failed: {:?}. UV was also unavailable: {:?}",
                        e, uv_error
                    ))
                })?;
            *pin_cache = Some(pin);
            Ok(token)
        }
        Some(false) => {
            if is_uv_blocked_error(&uv_error) {
                Err(passless_core::Error::Other(format_uv_blocked_message(
                    &uv_error,
                )))
            } else {
                Err(passless_core::Error::Other(format!(
                    "Credential management requires authentication but:\n\
                         - UV is unavailable: {:?}\n\
                         - No PIN is set on this authenticator\n\
                         \n\
                         Please set a PIN first using: passless client pin set <PIN>",
                    uv_error
                )))
            }
        }
        None => {
            if is_uv_blocked_error(&uv_error) {
                Err(passless_core::Error::Other(format_uv_blocked_message(
                    &uv_error,
                )))
            } else {
                Err(passless_core::Error::Other(format!(
                    "Credential management requires authentication but:\n\
                         - UV is unavailable: {:?}\n\
                         - This authenticator does not support PIN\n\
                         \n\
                         This authenticator may require built-in UV (biometric/fingerprint) \
                         which is currently blocked or unavailable.",
                    uv_error
                )))
            }
        }
    }
}

/// List all available FIDO2 authenticators
pub fn devices(output: OutputFormat) -> Result<()> {
    let list = TransportList::enumerate().map_err(|e| {
        passless_core::Error::Other(format!("Failed to enumerate authenticators: {:?}", e))
    })?;

    if list.is_empty() {
        return output_no_devices(output);
    }

    let devices = enumerate_device_info(&list);

    match output {
        OutputFormat::Plain => output_devices_plain(&devices),
        OutputFormat::Json => output_devices_json(&devices, list.len()),
    }

    Ok(())
}

/// Output message when no devices are found
fn output_no_devices(output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Plain => {
            println!("No FIDO2 authenticators found.\n");
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct DevicesOutput {
                count: usize,
                devices: Vec<String>,
            }
            let result = DevicesOutput {
                count: 0,
                devices: vec![],
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
    }
    Ok(())
}

/// Output device list in plain text format
fn output_devices_plain(devices: &[DeviceInfo]) {
    println!("Found {} FIDO2 authenticator(s):\n", devices.len());
    for device in devices {
        println!("  [{}] {} ({})", device.index, device.name, device.versions);
        if device.aaguid_hex != "unknown" && device.aaguid_hex != "unavailable" {
            println!("      AAGUID: {}", device.aaguid_hex);
        }
    }
    println!("\nUse --device <index> to select a specific device.");
}

/// Output device list in JSON format
fn output_devices_json(devices: &[DeviceInfo], total_count: usize) {
    #[derive(Serialize)]
    struct JsonDeviceInfo {
        index: usize,
        name: String,
        aaguid: String,
        versions: String,
    }

    #[derive(Serialize)]
    struct DevicesOutput {
        count: usize,
        devices: Vec<JsonDeviceInfo>,
    }

    let json_devices: Vec<JsonDeviceInfo> = devices
        .iter()
        .map(|d| JsonDeviceInfo {
            index: d.index,
            name: d.name.clone(),
            aaguid: d.aaguid_hex.clone(),
            versions: d.versions.clone(),
        })
        .collect();

    let result = DevicesOutput {
        count: total_count,
        devices: json_devices,
    };
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}

/// Get authenticator information
pub fn info(output: OutputFormat, device: Option<&str>) -> Result<()> {
    let mut transport = open_authenticator(device)?;

    if output == OutputFormat::Plain {
        println!("Querying authenticator information...\n");
    }

    let response = Client::authenticator_get_info(&mut transport)
        .map_err(|e| passless_core::Error::Other(format!("Failed to get info: {:?}", e)))?;

    // Parse CBOR response
    let info_value: soft_fido2_ctap::cbor::Value = soft_fido2_ctap::cbor::decode(&response)
        .map_err(|e| passless_core::Error::Other(format!("Failed to decode response: {:?}", e)))?;

    let info = parse_authenticator_info(&info_value)?;

    match output {
        OutputFormat::Plain => print_authenticator_info(&info),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&info).map_err(|e| {
                passless_core::Error::Other(format!("Failed to serialize to JSON: {:?}", e))
            })?;
            println!("{}", json);
        }
    }

    transport.close();
    Ok(())
}

/// Reset the authenticator
pub fn reset(output: OutputFormat, device: Option<&str>, confirm_count: u8) -> Result<()> {
    if confirm_count != 2 {
        return Err(passless_core::Error::Other(
            "Reset requires --yes-i-really-want-to-reset-my-device twice for safety".to_string(),
        ));
    }

    let mut transport = open_authenticator(device)?;

    if output == OutputFormat::Plain {
        println!("\nSending reset command...");
        println!("Please confirm user presence on the authenticator.");
    }

    // Send reset command (0x07) with no parameters
    let response = transport
        .send_ctap_command(0x07, &[], 30000)
        .map_err(|e| passless_core::Error::Other(format!("Reset failed: {:?}", e)))?;

    // Check status
    if !response.is_empty() && response[0] != 0x00 {
        return Err(passless_core::Error::Other(format!(
            "Reset failed with status: 0x{:02x}",
            response[0]
        )));
    }

    match output {
        OutputFormat::Plain => println!("Authenticator reset successfully!"),
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct ResetResult {
                success: bool,
                message: String,
            }
            let result = ResetResult {
                success: true,
                message: "Authenticator reset successfully".to_string(),
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
    }

    transport.close();
    Ok(())
}

/// List all credentials on the authenticator, optionally filtered by RP ID
pub fn list(output: OutputFormat, device: Option<&str>, rp_id_filter: Option<&str>) -> Result<()> {
    let mut transport = open_authenticator(device)?;

    if output == OutputFormat::Plain {
        if let Some(filter) = rp_id_filter {
            println!("Listing credentials for RP: {}...\n", filter);
        } else {
            println!("Listing all credentials on authenticator...\n");
        }
    }

    let pin_uv_auth = authenticate_for_credential_management_opt(&mut transport, output);

    // Get metadata (optional, only for plain output)
    if output == OutputFormat::Plain {
        println!("Credential Storage Metadata");
        println!("===========================");
        let request = CredentialManagementRequest::new(pin_uv_auth.clone());
        match Client::get_credentials_metadata(&mut transport, request) {
            Ok(metadata) => {
                println!(
                    "Existing discoverable credentials: {}",
                    metadata.existing_resident_credentials_count
                );
                println!(
                    "Max remaining credentials:         {}",
                    metadata.max_possible_remaining_resident_credentials_count
                );
                println!();
            }
            Err(e) => {
                println!("Could not get metadata: {:?}", e);
                println!("Continuing with enumeration...\n");
            }
        }
    }

    // Enumerate RPs
    if output == OutputFormat::Plain {
        println!("Relying Parties");
        println!("===============");
    }

    let request = CredentialManagementRequest::new(pin_uv_auth.clone());
    let rps = Client::enumerate_rps(&mut transport, request).map_err(|e| {
        passless_core::Error::Other(format!("Failed to enumerate relying parties: {:?}", e))
    })?;

    if rps.is_empty() {
        match output {
            OutputFormat::Plain => println!("No credentials found on this authenticator."),
            OutputFormat::Json => {
                let empty_output = ListOutput {
                    filter: rp_id_filter.map(|s| s.to_string()),
                    total_rps: 0,
                    filtered_rps: None,
                    total_credentials: 0,
                    relying_parties: vec![],
                };
                println!("{}", serde_json::to_string_pretty(&empty_output).unwrap());
            }
        }
        transport.close();
        return Ok(());
    }

    // Apply RP ID filter if specified
    let filtered_rps: Vec<_> = if let Some(filter) = rp_id_filter {
        rps.iter().filter(|rp| rp.id.contains(filter)).collect()
    } else {
        rps.iter().collect()
    };

    if filtered_rps.is_empty() {
        match output {
            OutputFormat::Plain => {
                if let Some(filter) = rp_id_filter {
                    println!("No credentials found for RP ID matching: {}", filter);
                } else {
                    println!("No credentials found on this authenticator.");
                }
            }
            OutputFormat::Json => {
                let empty_output = ListOutput {
                    filter: rp_id_filter.map(|s| s.to_string()),
                    total_rps: rps.len(),
                    filtered_rps: Some(0),
                    total_credentials: 0,
                    relying_parties: vec![],
                };
                println!("{}", serde_json::to_string_pretty(&empty_output).unwrap());
            }
        }
        transport.close();
        return Ok(());
    }

    if output == OutputFormat::Plain {
        if rp_id_filter.is_some() {
            println!(
                "Found {} matching relying part{} (filtered from {} total)\n",
                filtered_rps.len(),
                if filtered_rps.len() == 1 { "y" } else { "ies" },
                rps.len()
            );
        } else {
            println!(
                "Found {} relying part{}\n",
                filtered_rps.len(),
                if filtered_rps.len() == 1 { "y" } else { "ies" }
            );
        }
    }

    let mut total_credentials = 0;
    let mut rp_outputs = Vec::new();

    // For each RP, enumerate credentials
    for (rp_idx, rp) in filtered_rps.iter().enumerate() {
        if output == OutputFormat::Plain {
            println!("{}. Relying Party: {}", rp_idx + 1, rp.id);
            if let Some(name) = &rp.name {
                println!("   Name: {}", name);
            }
            println!("   RP ID Hash: {}", hex::encode(rp.rp_id_hash));
            println!();
        }

        let request = EnumerateCredentialsRequest::new(pin_uv_auth.clone(), rp.rp_id_hash);
        match Client::enumerate_credentials(&mut transport, request) {
            Ok(credentials) => {
                if output == OutputFormat::Plain {
                    if credentials.is_empty() {
                        println!("   No credentials found for this RP");
                    } else {
                        for (i, cred) in credentials.iter().enumerate() {
                            println!("   Credential {}:", i + 1);
                            println!("     User ID:       {}", hex::encode(&cred.user.id));
                            if let Some(name) = &cred.user.name {
                                println!("     User Name:     {}", name);
                            }
                            if let Some(display_name) = &cred.user.display_name {
                                println!("     Display Name:  {}", display_name);
                            }
                            // Show full credential ID for easy copy-paste
                            println!(
                                "     Credential ID: {}",
                                hex::encode(&cred.credential_id.id)
                            );

                            if let Some(cred_protect) = cred.cred_protect {
                                let protection_level = match cred_protect {
                                    1 => "UV Optional",
                                    2 => "UV Optional with Credential ID List",
                                    3 => "UV Required",
                                    _ => "Unknown",
                                };
                                println!(
                                    "     Protection:    {} ({})",
                                    protection_level, cred_protect
                                );
                            }

                            println!();
                        }
                        total_credentials += credentials.len();
                        println!("   Total credentials for this RP: {}", credentials.len());
                    }
                } else {
                    // JSON output: collect credentials
                    let cred_outputs: Vec<CredentialOutput> = credentials
                        .iter()
                        .map(|cred| CredentialOutput {
                            user_id: cred.user.id.clone(),
                            user_name: cred.user.name.clone(),
                            display_name: cred.user.display_name.clone(),
                            credential_id: cred.credential_id.id.clone(),
                            cred_protect: cred.cred_protect,
                        })
                        .collect();

                    total_credentials += cred_outputs.len();

                    rp_outputs.push(RpOutput {
                        id: rp.id.clone(),
                        name: rp.name.clone(),
                        rp_id_hash: rp.rp_id_hash.to_vec(),
                        credentials: cred_outputs,
                    });
                }
            }
            Err(e) => {
                if output == OutputFormat::Plain {
                    println!("   Failed to enumerate credentials: {:?}", e);
                }
            }
        }

        if output == OutputFormat::Plain {
            println!();
        }
    }

    match output {
        OutputFormat::Plain => {
            println!("Summary:");
            println!("========");
            if rp_id_filter.is_some() {
                println!(
                    "Total relying parties (filtered): {} (of {} total)",
                    filtered_rps.len(),
                    rps.len()
                );
            } else {
                println!("Total relying parties: {}", filtered_rps.len());
            }
            println!("Total credentials: {}", total_credentials);
        }
        OutputFormat::Json => {
            let list_output = ListOutput {
                filter: rp_id_filter.map(|s| s.to_string()),
                total_rps: rps.len(),
                filtered_rps: if rp_id_filter.is_some() {
                    Some(filtered_rps.len())
                } else {
                    None
                },
                total_credentials,
                relying_parties: rp_outputs,
            };
            println!("{}", serde_json::to_string_pretty(&list_output).unwrap());
        }
    }

    transport.close();
    Ok(())
}

/// Show detailed information about a specific credential
pub fn show(output: OutputFormat, device: Option<&str>, credential_id_hex: &str) -> Result<()> {
    if output == OutputFormat::Plain {
        println!("Showing credential: {}\n", credential_id_hex);
    }

    let mut transport = open_authenticator(device)?;

    let pin_uv_auth = authenticate_for_credential_management_opt(&mut transport, output);

    // Decode credential ID
    let credential_id = hex::decode(credential_id_hex)
        .map_err(|e| passless_core::Error::Other(format!("Invalid credential ID hex: {:?}", e)))?;

    // Enumerate RPs to find the credential
    let request = CredentialManagementRequest::new(pin_uv_auth.clone());
    let rps = Client::enumerate_rps(&mut transport, request).map_err(|e| {
        passless_core::Error::Other(format!("Failed to enumerate relying parties: {:?}", e))
    })?;

    let mut found_credential = None;
    let mut found_rp = None;

    for rp in rps {
        let enum_request = EnumerateCredentialsRequest::new(pin_uv_auth.clone(), rp.rp_id_hash);
        if let Ok(credentials) = Client::enumerate_credentials(&mut transport, enum_request) {
            for cred in credentials {
                if cred.credential_id.id == credential_id {
                    found_credential = Some(cred);
                    found_rp = Some(rp);
                    break;
                }
            }
            if found_credential.is_some() {
                break;
            }
        }
    }

    let credential = found_credential
        .ok_or_else(|| passless_core::Error::Other("Credential not found".to_string()))?;

    let rp = found_rp.unwrap();

    match output {
        OutputFormat::Plain => {
            println!("Credential Details");
            println!("==================\n");

            println!("Relying Party:");
            println!("  ID:           {}", rp.id);
            if let Some(name) = &rp.name {
                println!("  Name:         {}", name);
            }
            println!("  RP ID Hash:   {}", hex::encode(rp.rp_id_hash));
            println!();

            println!("User:");
            println!("  User ID:      {}", hex::encode(&credential.user.id));
            if let Some(name) = &credential.user.name {
                println!("  User Name:    {}", name);
            } else {
                println!("  User Name:    (not set)");
            }
            if let Some(display_name) = &credential.user.display_name {
                println!("  Display Name: {}", display_name);
            } else {
                println!("  Display Name: (not set)");
            }
            println!();

            println!("Credential:");
            println!(
                "  ID:           {}",
                hex::encode(&credential.credential_id.id)
            );
            println!("  Type:         {:?}", credential.credential_id.r#type);

            if let Some(cred_protect) = credential.cred_protect {
                let protection_level = match cred_protect {
                    1 => "UV Optional",
                    2 => "UV Optional with Credential ID List",
                    3 => "UV Required",
                    _ => "Unknown",
                };
                println!(
                    "  Protection:   {} (level {})",
                    protection_level, cred_protect
                );
            }

            if let Some(large_blob_key) = &credential.large_blob_key {
                println!("  Large Blob:   {} bytes", large_blob_key.len());
            }
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct ShowOutput {
                relying_party: RpInfo,
                user: UserInfo,
                credential: CredInfo,
            }

            #[derive(Serialize)]
            struct RpInfo {
                id: String,
                name: Option<String>,
                rp_id_hash: Vec<u8>,
            }

            #[derive(Serialize)]
            struct UserInfo {
                id: Vec<u8>,
                name: Option<String>,
                display_name: Option<String>,
            }

            #[derive(Serialize)]
            struct CredInfo {
                id: Vec<u8>,
                #[serde(rename = "type")]
                credential_type: String,
                cred_protect: Option<u8>,
                large_blob_key: Option<Vec<u8>>,
            }

            let output = ShowOutput {
                relying_party: RpInfo {
                    id: rp.id,
                    name: rp.name,
                    rp_id_hash: rp.rp_id_hash.to_vec(),
                },
                user: UserInfo {
                    id: credential.user.id,
                    name: credential.user.name,
                    display_name: credential.user.display_name,
                },
                credential: CredInfo {
                    id: credential.credential_id.id,
                    credential_type: format!("{:?}", credential.credential_id.r#type),
                    cred_protect: credential.cred_protect,
                    large_blob_key: credential.large_blob_key,
                },
            };
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
    }

    transport.close();
    Ok(())
}

/// Delete a credential by ID
pub fn delete(output: OutputFormat, device: Option<&str>, credential_id_hex: &str) -> Result<()> {
    if output == OutputFormat::Plain {
        println!("Deleting credential: {}\n", credential_id_hex);
    }

    let mut transport = open_authenticator(device)?;

    let pin_uv_auth = authenticate_for_credential_management_opt(&mut transport, output);

    // Decode credential ID
    let credential_id = hex::decode(credential_id_hex)
        .map_err(|e| passless_core::Error::Other(format!("Invalid credential ID hex: {:?}", e)))?;

    if output == OutputFormat::Plain {
        println!("Deleting credential...");
    }

    let request = DeleteCredentialRequest::new(pin_uv_auth, credential_id);
    Client::delete_credential(&mut transport, request).map_err(|e| {
        passless_core::Error::Other(format!("Failed to delete credential: {:?}", e))
    })?;

    match output {
        OutputFormat::Plain => println!("Credential deleted successfully!"),
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct DeleteResult {
                success: bool,
                credential_id: String,
            }
            let result = DeleteResult {
                success: true,
                credential_id: credential_id_hex.to_string(),
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
    }

    transport.close();
    Ok(())
}

/// Rename a credential (update user name and/or display name)
pub fn rename(
    output: OutputFormat,
    device: Option<&str>,
    credential_id_hex: &str,
    user_name: Option<&str>,
    display_name: Option<&str>,
) -> Result<()> {
    // Validate that at least one field is provided
    if user_name.is_none() && display_name.is_none() {
        return Err(passless_core::Error::Other(
            "At least one of --user-name or --display-name must be provided".to_string(),
        ));
    }

    if output == OutputFormat::Plain {
        println!("Renaming credential: {}\n", credential_id_hex);
    }

    let mut transport = open_authenticator(device)?;

    let pin_uv_auth = authenticate_for_credential_management_opt(&mut transport, output);

    // Decode credential ID
    let credential_id = hex::decode(credential_id_hex)
        .map_err(|e| passless_core::Error::Other(format!("Invalid credential ID hex: {:?}", e)))?;

    // First, we need to get the current credential to retrieve the user.id
    // We'll enumerate credentials and find the matching one
    if output == OutputFormat::Plain {
        println!("Fetching credential information...");
    }

    // Get authenticator info to check credential management support
    let info_response = Client::authenticator_get_info(&mut transport).map_err(|e| {
        passless_core::Error::Other(format!("Failed to get authenticator info: {:?}", e))
    })?;

    let info_value: soft_fido2_ctap::cbor::Value = soft_fido2_ctap::cbor::decode(&info_response)
        .map_err(|e| {
            passless_core::Error::Other(format!("Failed to decode info response: {:?}", e))
        })?;

    let info = parse_authenticator_info(&info_value)?;

    if !info
        .options
        .as_ref()
        .and_then(|opts| opts.get("credMgmt").or(opts.get("credentialMgmtPreview")))
        .copied()
        .unwrap_or(false)
    {
        return Err(passless_core::Error::Other(
            "Authenticator does not support credential management".to_string(),
        ));
    }

    // Enumerate all RPs to find the credential
    let mgmt_request = CredentialManagementRequest::new(pin_uv_auth.clone());
    let rps = Client::enumerate_rps(&mut transport, mgmt_request)
        .map_err(|e| passless_core::Error::Other(format!("Failed to enumerate RPs: {:?}", e)))?;

    let mut found_credential = None;

    for rp in rps {
        let enum_request = EnumerateCredentialsRequest::new(pin_uv_auth.clone(), rp.rp_id_hash);
        if let Ok(credentials) = Client::enumerate_credentials(&mut transport, enum_request) {
            for cred in credentials {
                if cred.credential_id.id == credential_id {
                    found_credential = Some(cred);
                    break;
                }
            }
            if found_credential.is_some() {
                break;
            }
        }
    }

    let credential = found_credential
        .ok_or_else(|| passless_core::Error::Other("Credential not found".to_string()))?;

    // Build updated user with the same user.id but potentially new name/display_name
    // Special handling: "-" means delete/clear the field (kubectl-style syntax)
    let updated_user = soft_fido2_ctap::User {
        id: credential.user.id.clone(),
        name: match user_name {
            Some("-") => None,                    // Clear the field
            Some(val) => Some(val.to_string()),   // Set new value
            None => credential.user.name.clone(), // Keep existing value
        },
        display_name: match display_name {
            Some("-") => None,                            // Clear the field
            Some(val) => Some(val.to_string()),           // Set new value
            None => credential.user.display_name.clone(), // Keep existing value
        },
    };

    if output == OutputFormat::Plain {
        println!("Updating user information...");
    }

    // Send the update request
    let update_request = UpdateUserRequest::new(pin_uv_auth, credential_id, updated_user.clone());
    Client::update_user_information(&mut transport, update_request).map_err(|e| {
        passless_core::Error::Other(format!("Failed to update user information: {:?}", e))
    })?;

    match output {
        OutputFormat::Plain => {
            println!("Credential renamed successfully!");

            // Show what was updated
            match user_name {
                Some("-") => println!("  User name: (cleared)"),
                Some(_) => {
                    if let Some(name) = &updated_user.name {
                        println!("  User name: {}", name);
                    }
                }
                None => {} // Not modified
            }

            match display_name {
                Some("-") => println!("  Display name: (cleared)"),
                Some(_) => {
                    if let Some(display) = &updated_user.display_name {
                        println!("  Display name: {}", display);
                    }
                }
                None => {} // Not modified
            }
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct RenameResult {
                success: bool,
                credential_id: String,
                user_name: Option<String>,
                display_name: Option<String>,
            }
            let result = RenameResult {
                success: true,
                credential_id: credential_id_hex.to_string(),
                user_name: updated_user.name,
                display_name: updated_user.display_name,
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
    }

    transport.close();
    Ok(())
}

fn vendor_pin_uv_auth(
    transport: &mut Transport,
    output: OutputFormat,
    auth_data: &[u8],
) -> Result<(u8, Vec<u8>)> {
    let token = authenticate_for_credential_management(transport, output)?;
    vendor_auth_from_token(transport, &token, auth_data)
}

/// Compute `(pinUvAuthProtocol, pinUvAuthParam)` over `auth_data` with an already obtained token.
fn vendor_auth_from_token(
    transport: &mut Transport,
    token: &soft_fido2::request::PinUvAuth,
    auth_data: &[u8],
) -> Result<(u8, Vec<u8>)> {
    let protocol = token.protocol_u8();
    let pin_protocol = match protocol {
        1 => PinProtocol::V1,
        _ => PinProtocol::V2,
    };
    let encapsulation =
        soft_fido2::PinUvAuthEncapsulation::new(transport, pin_protocol).map_err(|error| {
            passless_core::Error::Other(format!(
                "Failed to initialize PIN/UV authentication: {:?}",
                error
            ))
        })?;
    let param = encapsulation
        .authenticate(auth_data, token.param())
        .map_err(|error| {
            passless_core::Error::Other(format!(
                "Failed to authenticate vendor request: {:?}",
                error
            ))
        })?;
    Ok((protocol, param))
}

fn vendor_response_payload<'a>(response: &'a [u8], operation: &str) -> Result<&'a [u8]> {
    if response.is_empty() {
        return Err(passless_core::Error::Other(format!(
            "{} returned an empty response",
            operation
        )));
    }
    if response[0] == soft_fido2::StatusCode::Success as u8 {
        return Ok(&response[1..]);
    }
    if response[0] & 0xe0 == 0xa0 {
        return Ok(response);
    }
    Err(passless_core::Error::Other(format!(
        "{} failed with CTAP status 0x{:02x}",
        operation, response[0]
    )))
}

fn atomic_write_backup(path: &Path, data: &[u8]) -> Result<()> {
    if path.exists() {
        return Err(passless_core::Error::Other(format!(
            "Refusing to overwrite existing backup file: {}",
            path.display()
        )));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(passless_core::Error::Other(format!(
            "Backup destination directory does not exist: {}",
            parent.display()
        )));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            passless_core::Error::Other("Invalid backup destination filename".to_string())
        })?;
    let temp_path = parent.join(format!(
        ".{}.passless-tmp-{}-{}",
        file_name,
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temp_path, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result.map_err(|error| {
        passless_core::Error::Other(format!("Failed to write backup atomically: {}", error))
    })
}

fn read_backup(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|error| {
        passless_core::Error::Other(format!(
            "Failed to open backup file {}: {}",
            path.display(),
            error
        ))
    })?;
    let mut bundle = Vec::new();
    file.take((MAX_BACKUP_BUNDLE_SIZE + 1) as u64)
        .read_to_end(&mut bundle)
        .map_err(|error| {
            passless_core::Error::Other(format!("Failed to read backup file: {}", error))
        })?;
    if bundle.is_empty() || bundle.len() > MAX_BACKUP_BUNDLE_SIZE {
        return Err(passless_core::Error::Other(format!(
            "Invalid backup size: {} bytes",
            bundle.len()
        )));
    }
    Ok(bundle)
}

pub fn credential_backup(
    output: OutputFormat,
    device: Option<&str>,
    credential_id_hex: &str,
    recipient: &str,
    output_file: &PathBuf,
    confirm: bool,
) -> Result<()> {
    if !confirm {
        return Err(passless_core::Error::Other(
            "Credential export requires --yes-i-understand-this-exports-a-passkey".to_string(),
        ));
    }
    let credential_id = hex::decode(credential_id_hex).map_err(|error| {
        passless_core::Error::Other(format!("Invalid credential ID hex: {:?}", error))
    })?;
    let mut transport = open_authenticator(device)?;

    let prepare_auth_data = backup_prepare_auth_data(&credential_id, recipient);
    let (protocol, auth_param) = vendor_pin_uv_auth(&mut transport, output, &prepare_auth_data)?;
    let request = soft_fido2_ctap::cbor::MapBuilder::new()
        .insert(1, BACKUP_PREPARE_SUBCOMMAND)
        .and_then(|builder| builder.insert_bytes(2, &credential_id))
        .and_then(|builder| builder.insert(3, recipient))
        .and_then(|builder| builder.insert(4, protocol))
        .and_then(|builder| builder.insert_bytes(5, &auth_param))
        .and_then(|builder| builder.build())
        .map_err(|_| passless_core::Error::Other("Failed to encode backup request".to_string()))?;
    let response = transport
        .send_ctap_command(CMD_PASSLESS_BACKUP, &request, 30_000)
        .map_err(|error| {
            passless_core::Error::Other(format!("Credential backup failed: {:?}", error))
        })?;
    let payload = vendor_response_payload(&response, "Credential backup prepare")?;
    let parser = soft_fido2_ctap::cbor::MapParser::from_bytes(payload).map_err(|status| {
        passless_core::Error::Other(format!("Invalid backup response: {:?}", status))
    })?;
    let bundle = parser.get_bytes(1).map_err(|status| {
        passless_core::Error::Other(format!("Backup response omitted bundle: {:?}", status))
    })?;
    let token = parser.get_bytes(2).map_err(|status| {
        passless_core::Error::Other(format!("Backup response omitted token: {:?}", status))
    })?;
    atomic_write_backup(output_file, &bundle)?;

    let commit_auth_data = backup_commit_auth_data(&credential_id, &token);
    let (protocol, auth_param) = vendor_pin_uv_auth(&mut transport, output, &commit_auth_data)?;
    let commit_request = soft_fido2_ctap::cbor::MapBuilder::new()
        .insert(1, BACKUP_COMMIT_SUBCOMMAND)
        .and_then(|builder| builder.insert_bytes(2, &credential_id))
        .and_then(|builder| builder.insert_bytes(3, &token))
        .and_then(|builder| builder.insert(4, protocol))
        .and_then(|builder| builder.insert_bytes(5, &auth_param))
        .and_then(|builder| builder.build())
        .map_err(|_| passless_core::Error::Other("Failed to encode backup commit".to_string()))?;
    let commit_response = transport
        .send_ctap_command(CMD_PASSLESS_BACKUP, &commit_request, 30_000)
        .map_err(|error| {
            passless_core::Error::Other(format!(
                "Backup was written to {}, but authenticator finalization failed: {:?}",
                output_file.display(),
                error
            ))
        })?;
    vendor_response_payload(&commit_response, "Credential backup commit")?;
    transport.close();

    match output {
        OutputFormat::Plain => println!(
            "Credential backed up successfully to {}. Backup state is now BE=1, BS=1.",
            output_file.display()
        ),
        OutputFormat::Json => println!(
            "{}",
            serde_json::json!({
                "success": true,
                "credential_id": credential_id_hex,
                "path": output_file,
                "backup_eligible": true,
                "backed_up": true
            })
        ),
    }
    Ok(())
}

pub fn credential_restore(
    output: OutputFormat,
    device: Option<&str>,
    input_file: &Path,
    replace: bool,
    confirm: bool,
) -> Result<()> {
    if !confirm {
        return Err(passless_core::Error::Other(
            "Credential restore requires --yes-i-understand-this-restores-a-passkey".to_string(),
        ));
    }
    let bundle = read_backup(input_file)?;
    let mut transport = open_authenticator(device)?;
    let auth_data = restore_auth_data(&bundle, replace);
    let (protocol, auth_param) = vendor_pin_uv_auth(&mut transport, output, &auth_data)?;
    let request = soft_fido2_ctap::cbor::MapBuilder::new()
        .insert_bytes(1, &bundle)
        .and_then(|builder| builder.insert(2, replace))
        .and_then(|builder| builder.insert(3, protocol))
        .and_then(|builder| builder.insert_bytes(4, &auth_param))
        .and_then(|builder| builder.build())
        .map_err(|_| passless_core::Error::Other("Failed to encode restore request".to_string()))?;
    let response = transport
        .send_ctap_command(CMD_PASSLESS_RESTORE, &request, 30_000)
        .map_err(|error| {
            passless_core::Error::Other(format!("Credential restore failed: {:?}", error))
        })?;
    let payload = vendor_response_payload(&response, "Credential restore")?;
    let parser = soft_fido2_ctap::cbor::MapParser::from_bytes(payload).map_err(|status| {
        passless_core::Error::Other(format!("Invalid restore response: {:?}", status))
    })?;
    let credential_id = parser.get_bytes(1).map_err(|status| {
        passless_core::Error::Other(format!(
            "Restore response omitted credential ID: {:?}",
            status
        ))
    })?;
    transport.close();

    match output {
        OutputFormat::Plain => println!(
            "Credential {} restored successfully with BE=1, BS=1.",
            hex::encode(&credential_id)
        ),
        OutputFormat::Json => println!(
            "{}",
            serde_json::json!({
                "success": true,
                "credential_id": hex::encode(&credential_id),
                "replaced": replace,
                "backup_eligible": true,
                "backed_up": true
            })
        ),
    }
    Ok(())
}

/// What `set-cred-protect` applies to.
enum CredProtectTarget {
    Credential(Vec<u8>),
    Rp(String),
}

/// A credential as the authenticator lists it.
#[derive(Debug, Clone)]
struct RpCredential {
    id: Vec<u8>,
    rp_id: String,
    user_name: Option<String>,
    level: u8,
}

fn format_level(level: u8) -> String {
    format!("{} ({})", level, level_name(level))
}

/// What the user must know before lowering a level.
fn lowering_warning(level: u8) -> String {
    format!(
        "Lowering credProtect to {} weakens these credentials: they no longer require user \
         verification where the old level did.\n\
         With security.user_verification_authentication = false, level 1 means silent signing \
         by any process that can reach the authenticator's hidraw device.\n\
         Lowering has no effect while security.always_uv = true: the authenticator then forces \
         user verification whatever the level.",
        format_level(level)
    )
}

/// Explain a CTAP status returned by the set-cred-protect vendor command.
fn set_cred_protect_error(error: &soft_fido2::Error) -> String {
    use soft_fido2::StatusCode;

    let soft_fido2::Error::CtapError(code) = error else {
        return format!("Failed to change credProtect: {:?}", error);
    };
    let code = *code;
    let reason = if code == StatusCode::InvalidCommand as u8 {
        "this authenticator does not support set-cred-protect (it needs a Passless daemon \
         that provides it)"
            .to_string()
    } else if code == StatusCode::NoCredentials as u8 {
        "credential not found".to_string()
    } else if code == StatusCode::PuatRequired as u8
        || code == StatusCode::PinAuthInvalid as u8
        || code == StatusCode::UnauthorizedPermission as u8
    {
        "PIN/user verification was not accepted; nothing was changed".to_string()
    } else if code == StatusCode::OperationDenied as u8 {
        "the confirmation prompt on the authenticator was denied, closed or timed out; \
         nothing was changed"
            .to_string()
    } else if code == StatusCode::NotAllowed as u8 {
        "the authenticator refused to lower protection: no PIN is set and it auto-approves \
         prompts (PASSLESS_INTERACTION_MODE=automatic); set a PIN or use the desktop \
         interaction mode; nothing was changed"
            .to_string()
    } else if code == StatusCode::InvalidParameter as u8 {
        "the authenticator rejected the request parameters".to_string()
    } else {
        format!("CTAP status 0x{:02x}", code)
    };
    format!("Failed to change credProtect: {}", reason)
}

/// Suffix for failures once a change may have reached the authenticator.
const VERIFY_STATE_HINT: &str = "\n\nThe state may be partly changed: a failed batch is rolled back only best effort, \
     and with the pass backend a Git commit may already exist. Verify the current levels with \
     `passless client list`.";

/// Refuse to send a vendor command to anything that is not a Passless authenticator.
fn require_passless_authenticator(transport: &mut Transport) -> Result<()> {
    let info_response = Client::authenticator_get_info(transport).map_err(|e| {
        passless_core::Error::Other(format!("Failed to get authenticator info: {:?}", e))
    })?;
    let info_value: soft_fido2_ctap::cbor::Value = soft_fido2_ctap::cbor::decode(&info_response)
        .map_err(|e| {
            passless_core::Error::Other(format!("Failed to decode info response: {:?}", e))
        })?;
    let info = parse_authenticator_info(&info_value)?;
    if info.aaguid.as_deref() != Some(PASSLESS_AAGUID.as_slice()) {
        return Err(passless_core::Error::Other(
            "set-cred-protect is a Passless command and the selected device is not a Passless \
             authenticator; select the Passless device with --device"
                .to_string(),
        ));
    }
    Ok(())
}

/// Enumerate credentials with a token: every RP, or only `rp_id`.
fn enumerate_credentials_with(
    transport: &mut Transport,
    token: &soft_fido2::request::PinUvAuth,
    rp_filter: Option<&str>,
) -> Result<Vec<RpCredential>> {
    let rps = Client::enumerate_rps(
        transport,
        CredentialManagementRequest::new(Some(token.clone())),
    )
    .map_err(|e| passless_core::Error::Other(format!("Failed to enumerate RPs: {:?}", e)))?;

    let mut found = Vec::new();
    for rp in rps
        .into_iter()
        .filter(|rp| rp_filter.is_none_or(|filter| rp.id == filter))
    {
        let credentials = Client::enumerate_credentials(
            transport,
            EnumerateCredentialsRequest::new(Some(token.clone()), rp.rp_id_hash),
        )
        .map_err(|e| {
            passless_core::Error::Other(format!("Failed to enumerate credentials: {:?}", e))
        })?;
        found.extend(credentials.into_iter().map(|credential| RpCredential {
            id: credential.credential_id.id,
            rp_id: rp.id.clone(),
            user_name: credential.user.name,
            level: effective_level(credential.cred_protect),
        }));
    }
    Ok(found)
}

/// What `set_cred_protect` needs from the authenticator. A seam so the order of listing,
/// confirmation and change can be tested without a device.
trait CredProtectBackend {
    /// Which device this is, for the listing and the confirmation question.
    fn device_label(&self) -> String;
    /// Credentials of one RP (authenticated).
    fn list_rp(&mut self, rp_id: &str) -> Result<Vec<RpCredential>>;
    /// One credential by ID (authenticated).
    fn find(&mut self, credential_id: &[u8]) -> Result<RpCredential>;
    /// Authenticate afresh and send the change.
    fn change(&mut self, level: u8, credential_ids: &[Vec<u8>]) -> Result<Vec<CredProtectChange>>;
}

/// The real authenticator.
struct TransportBackend {
    transport: Transport,
    output: OutputFormat,
    pin_cache: PinCache,
    label: String,
}

impl TransportBackend {
    fn token(&mut self) -> Result<soft_fido2::request::PinUvAuth> {
        authenticate_for_credential_management_cached(
            &mut self.transport,
            self.output,
            &mut self.pin_cache,
        )
    }
}

impl CredProtectBackend for TransportBackend {
    fn device_label(&self) -> String {
        self.label.clone()
    }

    fn list_rp(&mut self, rp_id: &str) -> Result<Vec<RpCredential>> {
        let token = self.token()?;
        enumerate_credentials_with(&mut self.transport, &token, Some(rp_id))
    }

    fn find(&mut self, credential_id: &[u8]) -> Result<RpCredential> {
        let token = self.token()?;
        enumerate_credentials_with(&mut self.transport, &token, None)?
            .into_iter()
            .find(|credential| credential.id == credential_id)
            .ok_or_else(|| passless_core::Error::Other("Credential not found".to_string()))
    }

    fn change(&mut self, level: u8, credential_ids: &[Vec<u8>]) -> Result<Vec<CredProtectChange>> {
        let token = self.token()?;
        let auth_data = set_cred_protect_auth_data(level, credential_ids);
        let (protocol, auth_param) =
            vendor_auth_from_token(&mut self.transport, &token, &auth_data)?;
        let request =
            encode_request(level, credential_ids, protocol, &auth_param).map_err(|status| {
                passless_core::Error::Other(format!("Failed to encode request: {:?}", status))
            })?;
        let response = self
            .transport
            .send_ctap_command(CMD_PASSLESS_SET_CRED_PROTECT, &request, 30_000)
            .map_err(|error| passless_core::Error::Other(set_cred_protect_error(&error)))?;
        let payload = vendor_response_payload(&response, "Set credProtect")?;
        parse_response(payload).map_err(|status| {
            passless_core::Error::Other(format!("Invalid set-cred-protect response: {:?}", status))
        })
    }
}

fn print_credentials(label: &str, credentials: &[RpCredential]) {
    println!("Device: {}", label);
    for credential in credentials {
        println!(
            "  {}  RP: {}  user: {}  credProtect: {}",
            hex::encode(&credential.id),
            credential.rp_id,
            credential.user_name.as_deref().unwrap_or("(none)"),
            format_level(credential.level)
        );
    }
    println!();
}

/// List, confirm and change. Returns the credentials as listed and the authenticator's
/// per-credential result, or `None` when every credential already has `level`.
///
/// Nothing is sent to change anything before the confirmation (when one is due) has been given:
/// lowering asks unless `yes`; raising never asks.
fn plan_and_change<B: CredProtectBackend>(
    backend: &mut B,
    target: &CredProtectTarget,
    level: u8,
    yes: bool,
    plain: bool,
    confirm: &mut dyn FnMut(&str) -> Result<bool>,
) -> Result<(Vec<RpCredential>, Option<Vec<CredProtectChange>>)> {
    let label = backend.device_label();
    let listing = match target {
        CredProtectTarget::Rp(rp) => {
            let credentials = backend.list_rp(rp)?;
            if credentials.is_empty() {
                return Err(passless_core::Error::Other(format!(
                    "No credentials stored for RP '{}'",
                    rp
                )));
            }
            credentials
        }
        CredProtectTarget::Credential(id) => vec![backend.find(id)?],
    };
    if plain {
        print_credentials(&label, &listing);
    }

    if listing.iter().all(|credential| credential.level == level) {
        return Ok((listing, None));
    }

    if listing.iter().any(|credential| credential.level > level) {
        if plain {
            println!("{}\n", lowering_warning(level));
        }
        if !yes {
            let subject = match target {
                CredProtectTarget::Rp(rp) => {
                    format!("{} credential(s) of RP '{}'", listing.len(), rp)
                }
                CredProtectTarget::Credential(_) => {
                    let credential = &listing[0];
                    format!(
                        "credential {} (RP '{}', user {})",
                        hex::encode(&credential.id),
                        credential.rp_id,
                        credential.user_name.as_deref().unwrap_or("(none)")
                    )
                }
            };
            let question = format!(
                "Lower credProtect to {} for {} on {}?",
                format_level(level),
                subject,
                label
            );
            if !confirm(&question)? {
                return Err(passless_core::Error::Other(
                    "Cancelled; nothing was changed".to_string(),
                ));
            }
        }
    }

    let ids: Vec<Vec<u8>> = listing.iter().map(|c| c.id.clone()).collect();
    let changes = backend
        .change(level, &ids)
        .map_err(|error| passless_core::Error::Other(format!("{}{}", error, VERIFY_STATE_HINT)))?;
    Ok((listing, Some(changes)))
}

/// Ask a yes/no question; anything but "y" or "yes" (also end of input) is no.
fn confirm<R: std::io::BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    question: &str,
) -> Result<bool> {
    write!(writer, "{} [y/N]: ", question)
        .and_then(|_| writer.flush())
        .map_err(|e| passless_core::Error::Other(format!("Failed to write prompt: {}", e)))?;
    let mut answer = String::new();
    reader
        .read_line(&mut answer)
        .map_err(|e| passless_core::Error::Other(format!("Failed to read answer: {}", e)))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Validate the arguments of `set-cred-protect` without touching a device.
fn parse_cred_protect_target(
    output: OutputFormat,
    credential_id_hex: Option<&str>,
    rp_id: Option<&str>,
    level: u8,
    yes: bool,
) -> Result<CredProtectTarget> {
    if !(MIN_CRED_PROTECT_LEVEL..=MAX_CRED_PROTECT_LEVEL).contains(&level) {
        return Err(passless_core::Error::Other(format!(
            "--level must be between {} and {}",
            MIN_CRED_PROTECT_LEVEL, MAX_CRED_PROTECT_LEVEL
        )));
    }
    let target = match (credential_id_hex, rp_id) {
        (Some(id), None) => CredProtectTarget::Credential(hex::decode(id).map_err(|e| {
            passless_core::Error::Other(format!("Invalid credential ID hex: {:?}", e))
        })?),
        (None, Some(rp)) if !rp.is_empty() => CredProtectTarget::Rp(rp.to_string()),
        _ => {
            return Err(passless_core::Error::Other(
                "Give exactly one of --id <CREDENTIAL_ID> and --rp <RP_ID>".to_string(),
            ));
        }
    };
    // JSON output cannot carry a question: lowering (or any --rp change) must be pre-approved.
    let may_ask = match target {
        CredProtectTarget::Rp(_) => true,
        CredProtectTarget::Credential(_) => level < MAX_CRED_PROTECT_LEVEL,
    };
    if output == OutputFormat::Json && may_ask && !yes {
        return Err(passless_core::Error::Other(
            "-o json cannot ask for confirmation here; pass --yes".to_string(),
        ));
    }
    Ok(target)
}

/// Change the stored credProtect level of one credential (`--id`) or every credential of an RP
/// (`--rp`) through the running authenticator.
///
/// Always authorized by a credential-management pinUvAuthToken (PIN, or built-in user
/// verification when no PIN is set); there is no fallback without a token. The credentials are
/// looked up and shown first, and lowering asks for confirmation unless `--yes`. Two tokens are
/// used (look up, then change) because a token authorizes new requests for only a few seconds;
/// a typed PIN is reused.
pub fn set_cred_protect(
    output: OutputFormat,
    device: Option<&str>,
    credential_id_hex: Option<&str>,
    rp_id: Option<&str>,
    level: u8,
    yes: bool,
) -> Result<()> {
    let target = parse_cred_protect_target(output, credential_id_hex, rp_id, level, yes)?;

    let mut transport = open_authenticator(device)?;
    require_passless_authenticator(&mut transport)?;
    let label = match device {
        Some(selector) if selector.parse::<usize>().is_ok() => {
            format!("device index {} (Passless authenticator)", selector)
        }
        Some(selector) => format!("device '{}' (Passless authenticator)", selector),
        None => "default device, the newest one (Passless authenticator)".to_string(),
    };
    let mut backend = TransportBackend {
        transport,
        output,
        pin_cache: None,
        label,
    };

    let stdin = std::io::stdin();
    let mut ask = |question: &str| confirm(&mut stdin.lock(), &mut std::io::stdout(), question);
    let result = plan_and_change(
        &mut backend,
        &target,
        level,
        yes,
        output == OutputFormat::Plain,
        &mut ask,
    );
    backend.transport.close();
    let (listing, changes) = result?;

    print_cred_protect_result(output, &target, &listing, level, changes.as_deref());
    Ok(())
}

fn print_cred_protect_result(
    output: OutputFormat,
    target: &CredProtectTarget,
    listing: &[RpCredential],
    level: u8,
    changes: Option<&[CredProtectChange]>,
) {
    // `None` means every credential already had the level: report them as unchanged.
    let synthesized: Vec<CredProtectChange>;
    let changes = match changes {
        Some(changes) => changes,
        None => {
            synthesized = listing
                .iter()
                .map(|credential| CredProtectChange {
                    credential_id: credential.id.clone(),
                    previous: credential.level,
                    current: level,
                })
                .collect();
            if output == OutputFormat::Plain {
                println!(
                    "All {} credential(s) already have credProtect {}; nothing to do.",
                    listing.len(),
                    format_level(level)
                );
            }
            &synthesized
        }
    };
    let user_of = |id: &[u8]| {
        listing
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| c.user_name.clone())
    };
    match output {
        OutputFormat::Plain => {
            for change in changes {
                let user = user_of(&change.credential_id)
                    .map(|name| format!(" (user: {})", name))
                    .unwrap_or_default();
                if change.previous == change.current {
                    println!(
                        "Credential {}{}: credProtect already {}; unchanged",
                        hex::encode(&change.credential_id),
                        user,
                        format_level(change.current)
                    );
                } else {
                    println!(
                        "Credential {}{}: credProtect {} -> {}",
                        hex::encode(&change.credential_id),
                        user,
                        format_level(change.previous),
                        format_level(change.current)
                    );
                }
            }
        }
        OutputFormat::Json => {
            let rp = match target {
                CredProtectTarget::Rp(rp) => Some(rp.as_str()),
                CredProtectTarget::Credential(_) => None,
            };
            println!(
                "{}",
                serde_json::json!({
                    "success": true,
                    "rp_id": rp,
                    "level": level,
                    "credentials": changes.iter().map(|change| serde_json::json!({
                        "credential_id": hex::encode(&change.credential_id),
                        "rp_id": listing.iter().find(|c| c.id == change.credential_id).map(|c| c.rp_id.clone()),
                        "previous_level": change.previous,
                        "level": change.current,
                        "changed": change.previous != change.current,
                    })).collect::<Vec<_>>(),
                })
            );
        }
    }
}

/// Set PIN on authenticator
pub fn pin_set(output: OutputFormat, device: Option<&str>, pin: &str) -> Result<()> {
    // Validate PIN length (CTAP2 spec: 4-63 UTF-8 bytes)
    if pin.len() < 4 {
        return Err(passless_core::Error::Other(
            "PIN must be at least 4 characters".to_string(),
        ));
    }
    if pin.len() > 63 {
        return Err(passless_core::Error::Other(
            "PIN must be at most 63 bytes in UTF-8".to_string(),
        ));
    }

    let mut transport = open_authenticator(device)?;

    if output == OutputFormat::Plain {
        println!("Setting PIN on authenticator...\n");
    }

    // Get authenticator info to check PIN capability
    let info_response = Client::authenticator_get_info(&mut transport).map_err(|e| {
        passless_core::Error::Other(format!("Failed to get authenticator info: {:?}", e))
    })?;

    let info_value: soft_fido2_ctap::cbor::Value = soft_fido2_ctap::cbor::decode(&info_response)
        .map_err(|e| passless_core::Error::Other(format!("Failed to decode info: {:?}", e)))?;

    let info = parse_authenticator_info(&info_value)?;

    // Check if PIN is supported
    // According to CTAP spec:
    // - clientPin: true = PIN capability AND PIN is set
    // - clientPin: false = PIN capability but PIN is NOT set
    // - clientPin absent = no PIN capability
    // So we check for key presence, not the value
    let options = info.options.as_ref();
    let client_pin_supported = options
        .map(|opts| opts.contains_key("clientPin"))
        .unwrap_or(false);

    if !client_pin_supported {
        return Err(passless_core::Error::Other(
            "Authenticator does not support PIN (clientPin not available)".to_string(),
        ));
    }

    // Use soft-fido2 PIN protocol implementation
    let mut encapsulation =
        soft_fido2::PinUvAuthEncapsulation::new(&mut transport, soft_fido2::PinProtocol::V2)
            .map_err(|e| {
                passless_core::Error::Other(format!("Failed to initialize PIN protocol: {:?}", e))
            })?;

    encapsulation
        .set_pin(&mut transport, pin)
        .map_err(|e| passless_core::Error::Other(format!("Failed to set PIN: {:?}", e)))?;

    match output {
        OutputFormat::Plain => {
            println!("PIN set successfully!");
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct PinSetResult {
                success: bool,
                message: String,
            }
            let result = PinSetResult {
                success: true,
                message: "PIN set successfully".to_string(),
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
    }

    transport.close();
    Ok(())
}

/// Change PIN on authenticator
pub fn pin_change(
    output: OutputFormat,
    device: Option<&str>,
    old_pin: &str,
    new_pin: &str,
) -> Result<()> {
    // Validate inputs
    if old_pin.is_empty() {
        return Err(passless_core::Error::Other(
            "Current PIN is required".to_string(),
        ));
    }
    if new_pin.len() < 4 {
        return Err(passless_core::Error::Other(
            "New PIN must be at least 4 characters".to_string(),
        ));
    }
    if new_pin.len() > 63 {
        return Err(passless_core::Error::Other(
            "New PIN must be at most 63 bytes in UTF-8".to_string(),
        ));
    }

    let mut transport = open_authenticator(device)?;

    if output == OutputFormat::Plain {
        println!("Changing PIN on authenticator...\n");
    }

    // Get authenticator info to verify PIN is set
    let info_response = Client::authenticator_get_info(&mut transport).map_err(|e| {
        passless_core::Error::Other(format!("Failed to get authenticator info: {:?}", e))
    })?;

    let info_value: soft_fido2_ctap::cbor::Value = soft_fido2_ctap::cbor::decode(&info_response)
        .map_err(|e| passless_core::Error::Other(format!("Failed to decode info: {:?}", e)))?;

    let info = parse_authenticator_info(&info_value)?;

    // Check if PIN is set
    let options = info.options.as_ref();
    let client_pin_set = options
        .and_then(|opts| opts.get("clientPin"))
        .copied()
        .unwrap_or(false);

    if !client_pin_set {
        return Err(passless_core::Error::Other(
            "No PIN is currently set on this authenticator. Use 'pin set' instead.".to_string(),
        ));
    }

    // Use soft-fido2 PIN protocol implementation
    let mut encapsulation =
        soft_fido2::PinUvAuthEncapsulation::new(&mut transport, soft_fido2::PinProtocol::V2)
            .map_err(|e| {
                passless_core::Error::Other(format!("Failed to initialize PIN protocol: {:?}", e))
            })?;

    encapsulation
        .change_pin(&mut transport, old_pin, new_pin)
        .map_err(|e| passless_core::Error::Other(format!("Failed to change PIN: {:?}", e)))?;

    match output {
        OutputFormat::Plain => {
            println!("PIN changed successfully!");
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct PinChangeResult {
                success: bool,
                message: String,
            }
            let result = PinChangeResult {
                success: true,
                message: "PIN changed successfully".to_string(),
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
    }

    transport.close();
    Ok(())
}

/// Extract the restored UV retry count from a `0x42` reset response.
///
/// The transport has already stripped the CTAP status byte, so `response` is
/// the bare CBOR map `{1: uvRetries}`. Returns `None` when the authenticator
/// sent no payload, an empty map, or a map without key 1: the reset still
/// succeeded in that case, the count is just unknown.
fn parse_uv_retries_reset_response(response: &[u8]) -> Option<u8> {
    if response.is_empty() {
        return None;
    }

    let soft_fido2_ctap::cbor::Value::Map(map) =
        soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(response).ok()?
    else {
        return None;
    };

    map.iter()
        .find(|(k, _)| *k == soft_fido2_ctap::cbor::Value::Integer(1))
        .and_then(|(_, v)| match v {
            soft_fido2_ctap::cbor::Value::Integer(n) => u8::try_from(*n).ok(),
            _ => None,
        })
}

/// Reset built-in user verification retries on authenticator
pub fn pin_uv_reset(output: OutputFormat, device: Option<&str>) -> Result<()> {
    let mut transport = open_authenticator(device)?;

    // Get authenticator info to determine PIN status
    let info_response = Client::authenticator_get_info(&mut transport).map_err(|e| {
        passless_core::Error::Other(format!("Failed to get authenticator info: {:?}", e))
    })?;

    let info_value: soft_fido2_ctap::cbor::Value = soft_fido2_ctap::cbor::decode(&info_response)
        .map_err(|e| {
            passless_core::Error::Other(format!("Failed to decode info response: {:?}", e))
        })?;

    let info = parse_authenticator_info(&info_value)?;

    let client_pin_set = info
        .options
        .as_ref()
        .and_then(|opts| opts.get("clientPin").copied())
        .unwrap_or(false);

    let payload_bytes = if client_pin_set {
        // PIN-authenticated flow
        if output == OutputFormat::Plain {
            println!("Resetting built-in user verification retries...");
            println!("Enter PIN: ");
        }

        let pin = read_password()
            .map_err(|e| passless_core::Error::Other(format!("Failed to read PIN: {:?}", e)))?;

        if pin.is_empty() {
            return Err(passless_core::Error::Other(
                "PIN is required for authenticated UV retry reset".to_string(),
            ));
        }

        if output == OutputFormat::Plain {
            println!();
        }

        // Determine the preferred pinUvAuthProtocol
        let pin_uv_auth_protocol = info
            .pin_uv_auth_protocols
            .as_ref()
            .and_then(|protocols| protocols.last())
            .copied()
            .unwrap_or(1);

        // Get a PIN token for credential management
        let mut encapsulation = soft_fido2::PinUvAuthEncapsulation::new(
            &mut transport,
            match pin_uv_auth_protocol {
                1 => soft_fido2::PinProtocol::V1,
                2 => soft_fido2::PinProtocol::V2,
                _ => soft_fido2::PinProtocol::V2,
            },
        )
        .map_err(|e| {
            passless_core::Error::Other(format!("Failed to initialize PIN protocol: {:?}", e))
        })?;

        let permissions = soft_fido2::request::Permission::CredentialManagement as u8;
        let pin_token_bytes = encapsulation
            .get_pin_uv_auth_token_using_pin_with_permissions(
                &mut transport,
                &pin,
                permissions,
                None,
            )
            .map_err(|e| {
                passless_core::Error::Other(format!("Failed to get PIN token: {:?}", e))
            })?;

        let auth_data = [CMD_PASSLESS_RESET_UV_RETRIES, RESET_UV_RETRIES_SUBCOMMAND];

        let pin_uv_auth_param = encapsulation
            .authenticate(&auth_data, &pin_token_bytes)
            .map_err(|e| {
                passless_core::Error::Other(format!("Failed to compute PIN UV auth param: {:?}", e))
            })?;

        if output == OutputFormat::Plain {
            println!("Sending authenticated UV retry reset command...");
        }

        // Build authenticated payload
        soft_fido2_ctap::cbor::MapBuilder::new()
            .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
            .map_err(|_| passless_core::Error::Other("Failed to build CBOR payload".to_string()))?
            .insert(3, pin_uv_auth_protocol)
            .map_err(|_| passless_core::Error::Other("Failed to build CBOR payload".to_string()))?
            .insert_bytes(4, &pin_uv_auth_param)
            .map_err(|_| passless_core::Error::Other("Failed to build CBOR payload".to_string()))?
            .build()
            .map_err(|_| passless_core::Error::Other("Failed to build CBOR payload".to_string()))?
    } else {
        // No PIN configured - send unauthenticated reset command
        if output == OutputFormat::Plain {
            println!("No PIN configured; resetting UV retries directly...");
        }

        soft_fido2_ctap::cbor::MapBuilder::new()
            .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
            .map_err(|_| passless_core::Error::Other("Failed to build CBOR payload".to_string()))?
            .build()
            .map_err(|_| passless_core::Error::Other("Failed to build CBOR payload".to_string()))?
    };

    // Send command 0x42 with the CBOR payload.
    //
    // `send_ctap_command` parses and consumes the CTAP status byte, surfacing a
    // non-zero status as `Err`. Reaching this point therefore means the reset
    // already succeeded, and `response` holds only the bare CBOR response map.
    let response = transport
        .send_ctap_command(CMD_PASSLESS_RESET_UV_RETRIES, &payload_bytes, 30000)
        .map_err(|e| passless_core::Error::Other(format!("UV retry reset failed: {:?}", e)))?;

    let uv_retries_count = parse_uv_retries_reset_response(&response);

    match output {
        OutputFormat::Plain => {
            if let Some(count) = uv_retries_count {
                println!(
                    "UV retries reset successfully! Restored to {} attempts.",
                    count
                );
            } else {
                println!("UV retries reset successfully!");
                println!("Note: The retry counter has been restored to the configured maximum.");
            }
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct PinUvResetResult {
                success: bool,
                message: String,
                #[serde(skip_serializing_if = "Option::is_none")]
                uv_retries: Option<u8>,
            }
            let result = PinUvResetResult {
                success: true,
                message: "UV retries reset successfully".to_string(),
                uv_retries: uv_retries_count,
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
    }

    transport.close();
    Ok(())
}

#[derive(Debug, Default, Serialize)]
struct AuthenticatorInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    versions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions: Option<Vec<String>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_hex_option"
    )]
    aaguid: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<HashMap<String, bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_msg_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pin_uv_auth_protocols: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_credential_count_in_list: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_credential_id_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transports: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_discoverable_credentials: Option<u32>,
}

fn serialize_hex_option<S>(
    data: &Option<Vec<u8>>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match data {
        Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
        None => serializer.serialize_none(),
    }
}

fn parse_authenticator_info(value: &soft_fido2_ctap::cbor::Value) -> Result<AuthenticatorInfo> {
    use soft_fido2_ctap::cbor::Value;

    let map = match value {
        Value::Map(m) => m,
        _ => return Err(passless_core::Error::Other("Expected CBOR map".to_string())),
    };

    let mut info = AuthenticatorInfo::default();

    for (key, val) in map {
        let key_int = match key {
            Value::Integer(i) => *i as u32,
            _ => continue,
        };

        match key_int {
            1 => {
                // versions
                if let Value::Array(arr) = val {
                    info.versions = Some(
                        arr.iter()
                            .filter_map(|v| match v {
                                Value::Text(s) => Some(s.clone()),
                                _ => None,
                            })
                            .collect(),
                    );
                }
            }
            2 => {
                // extensions
                if let Value::Array(arr) = val {
                    info.extensions = Some(
                        arr.iter()
                            .filter_map(|v| match v {
                                Value::Text(s) => Some(s.clone()),
                                _ => None,
                            })
                            .collect(),
                    );
                }
            }
            3 => {
                // aaguid
                if let Value::Bytes(b) = val {
                    info.aaguid = Some(b.clone());
                }
            }
            4 => {
                // options
                if let Value::Map(opts) = val {
                    let mut options_map = HashMap::new();
                    for (opt_key, opt_val) in opts {
                        if let (Value::Text(k), Value::Bool(v)) = (opt_key, opt_val) {
                            options_map.insert(k.clone(), *v);
                        }
                    }
                    info.options = Some(options_map);
                }
            }
            5 => {
                // maxMsgSize
                if let Value::Integer(n) = val {
                    info.max_msg_size = Some(*n as u32);
                }
            }
            6 => {
                // pinUvAuthProtocols
                if let Value::Array(arr) = val {
                    info.pin_uv_auth_protocols = Some(
                        arr.iter()
                            .filter_map(|v| match v {
                                Value::Integer(i) => Some(*i as u8),
                                _ => None,
                            })
                            .collect(),
                    );
                }
            }
            7 => {
                // maxCredentialCountInList
                if let Value::Integer(n) = val {
                    info.max_credential_count_in_list = Some(*n as u32);
                }
            }
            8 => {
                // maxCredentialIdLength
                if let Value::Integer(n) = val {
                    info.max_credential_id_length = Some(*n as u32);
                }
            }
            9 => {
                // transports
                if let Value::Array(arr) = val {
                    info.transports = Some(
                        arr.iter()
                            .filter_map(|v| match v {
                                Value::Text(s) => Some(s.clone()),
                                _ => None,
                            })
                            .collect(),
                    );
                }
            }
            0x14 => {
                // remainingDiscoverableCredentials
                if let Value::Integer(n) = val {
                    info.remaining_discoverable_credentials = Some(*n as u32);
                }
            }
            _ => {}
        }
    }

    Ok(info)
}

fn print_authenticator_info(info: &AuthenticatorInfo) {
    println!("Authenticator Information:");
    println!("==========================");

    if let Some(versions) = &info.versions {
        println!("FIDO Versions: {}", versions.join(", "));
    }

    if let Some(extensions) = &info.extensions {
        println!("Extensions: {}", extensions.join(", "));
    }

    if let Some(aaguid) = &info.aaguid {
        println!("AAGUID: {}", hex::encode(aaguid));
    }

    if let Some(options) = &info.options {
        println!("\nOptions:");
        for (key, value) in options {
            println!("  {}: {}", key, value);
        }
    }

    if let Some(max_msg_size) = info.max_msg_size {
        println!("\nMax Message Size: {} bytes", max_msg_size);
    }

    if let Some(pin_protocols) = &info.pin_uv_auth_protocols {
        println!("PIN/UV Auth Protocols: {:?}", pin_protocols);
    }

    if let Some(max_creds) = info.max_credential_count_in_list {
        println!("Max Credentials in List: {}", max_creds);
    }

    if let Some(max_cred_id_len) = info.max_credential_id_length {
        println!("Max Credential ID Length: {}", max_cred_id_len);
    }

    if let Some(transports) = &info.transports {
        println!("Transports: {}", transports.join(", "));
    }

    if let Some(remaining) = info.remaining_discoverable_credentials {
        println!("\nRemaining Discoverable Credentials: {}", remaining);
    }
}

#[cfg(test)]
mod uv_reset_response_tests {
    use super::parse_uv_retries_reset_response;

    #[test]
    fn parses_uv_retries_from_bare_cbor_map() {
        // What the authenticator returns once the transport has stripped the
        // status byte: CBOR {1: 8}. A previous version of the client treated
        // the 0xa1 map header as a CTAP status code and reported a successful
        // reset as "status: 0xa1".
        assert_eq!(
            parse_uv_retries_reset_response(&[0xa1, 0x01, 0x08]),
            Some(8)
        );
    }

    #[test]
    fn handles_responses_without_a_count() {
        // Empty body, empty map, and a map lacking key 1 are all successful
        // resets with an unknown count.
        assert_eq!(parse_uv_retries_reset_response(&[]), None);
        assert_eq!(parse_uv_retries_reset_response(&[0xa0]), None);
        assert_eq!(parse_uv_retries_reset_response(&[0xa1, 0x02, 0x08]), None);
    }

    #[test]
    fn handles_malformed_cbor() {
        assert_eq!(parse_uv_retries_reset_response(&[0xa1, 0x01]), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    fn error_text(result: Result<()>) -> String {
        result.expect_err("expected an error").to_string()
    }

    #[test]
    fn confirm_accepts_only_yes() {
        for (answer, expected) in [
            ("y\n", true),
            ("Y\n", true),
            ("yes\n", true),
            (" YES \n", true),
            ("n\n", false),
            ("\n", false),
            ("", false),
            ("yep\n", false),
            ("1\n", false),
        ] {
            let mut output = Vec::new();
            let result = confirm(&mut Cursor::new(answer), &mut output, "Proceed?").unwrap();
            assert_eq!(result, expected, "answer {answer:?}");
            assert_eq!(String::from_utf8(output).unwrap(), "Proceed? [y/N]: ");
        }
    }

    // These all fail before any authenticator is opened: no test here reaches a device.
    #[test]
    fn set_cred_protect_validates_arguments_before_touching_a_device() {
        let id = "ab".repeat(32);

        let message = error_text(set_cred_protect(
            OutputFormat::Plain,
            None,
            Some(&id),
            None,
            0,
            false,
        ));
        assert!(message.contains("--level"), "{message}");
        let message = error_text(set_cred_protect(
            OutputFormat::Plain,
            None,
            Some(&id),
            None,
            4,
            false,
        ));
        assert!(message.contains("--level"), "{message}");

        let message = error_text(set_cred_protect(
            OutputFormat::Plain,
            None,
            None,
            None,
            1,
            false,
        ));
        assert!(message.contains("exactly one"), "{message}");
        let message = error_text(set_cred_protect(
            OutputFormat::Plain,
            None,
            Some(&id),
            Some("ssh:"),
            1,
            false,
        ));
        assert!(message.contains("exactly one"), "{message}");
        let message = error_text(set_cred_protect(
            OutputFormat::Plain,
            None,
            None,
            Some(""),
            1,
            false,
        ));
        assert!(message.contains("exactly one"), "{message}");

        let message = error_text(set_cred_protect(
            OutputFormat::Plain,
            None,
            Some("not-hex"),
            None,
            1,
            false,
        ));
        assert!(message.contains("Invalid credential ID"), "{message}");

        let message = error_text(set_cred_protect(
            OutputFormat::Json,
            None,
            None,
            Some("ssh:"),
            1,
            false,
        ));
        assert!(message.contains("--yes"), "{message}");
    }

    #[test]
    fn set_cred_protect_errors_explain_the_ctap_status() {
        use soft_fido2::StatusCode;

        let text = |status: StatusCode| {
            set_cred_protect_error(&soft_fido2::Error::CtapError(status as u8))
        };
        assert!(text(StatusCode::InvalidCommand).contains("does not support"));
        assert!(text(StatusCode::NoCredentials).contains("not found"));
        for status in [
            StatusCode::PuatRequired,
            StatusCode::PinAuthInvalid,
            StatusCode::UnauthorizedPermission,
        ] {
            assert!(text(status).contains("nothing was changed"));
        }
        assert!(text(StatusCode::Other).contains("0x"));
    }

    #[test]
    fn levels_are_shown_with_their_names() {
        assert_eq!(format_level(1), "1 (userVerificationOptional)");
        assert_eq!(
            format_level(2),
            "2 (userVerificationOptionalWithCredentialIDList)"
        );
        assert_eq!(format_level(3), "3 (userVerificationRequired)");
    }

    /// Records the calls `plan_and_change` makes, in order.
    struct FakeBackend {
        calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        credentials: Vec<RpCredential>,
        change_error: Option<String>,
    }

    impl FakeBackend {
        fn new(levels: &[u8]) -> Self {
            Self {
                calls: Default::default(),
                credentials: levels
                    .iter()
                    .enumerate()
                    .map(|(n, level)| RpCredential {
                        id: vec![n as u8 + 1; 32],
                        rp_id: "ssh:".to_string(),
                        user_name: Some(format!("key-{n}")),
                        level: *level,
                    })
                    .collect(),
                change_error: None,
            }
        }
    }

    impl CredProtectBackend for FakeBackend {
        fn device_label(&self) -> String {
            "device index 7 (test)".to_string()
        }

        fn list_rp(&mut self, rp_id: &str) -> Result<Vec<RpCredential>> {
            self.calls.borrow_mut().push(format!("list_rp {rp_id}"));
            Ok(self.credentials.clone())
        }

        fn find(&mut self, credential_id: &[u8]) -> Result<RpCredential> {
            self.calls.borrow_mut().push("find".to_string());
            self.credentials
                .iter()
                .find(|c| c.id == credential_id)
                .cloned()
                .ok_or_else(|| passless_core::Error::Other("Credential not found".to_string()))
        }

        fn change(
            &mut self,
            level: u8,
            credential_ids: &[Vec<u8>],
        ) -> Result<Vec<CredProtectChange>> {
            self.calls
                .borrow_mut()
                .push(format!("change {level} x{}", credential_ids.len()));
            if let Some(error) = &self.change_error {
                return Err(passless_core::Error::Other(error.clone()));
            }
            Ok(credential_ids
                .iter()
                .map(|id| {
                    let previous = self
                        .credentials
                        .iter()
                        .find(|c| &c.id == id)
                        .map_or(1, |c| c.level);
                    CredProtectChange {
                        credential_id: id.clone(),
                        previous,
                        current: level,
                    }
                })
                .collect())
        }
    }

    type PlanResult = Result<(Vec<RpCredential>, Option<Vec<CredProtectChange>>)>;

    /// Run `plan_and_change` with a confirm function that records its questions.
    fn run_plan(
        backend: &mut FakeBackend,
        target: &CredProtectTarget,
        level: u8,
        yes: bool,
        answer: bool,
    ) -> (PlanResult, Vec<String>) {
        let mut questions = Vec::new();
        let calls = backend.calls.clone();
        let mut ask = |question: &str| {
            calls.borrow_mut().push("confirm".to_string());
            questions.push(question.to_string());
            Ok(answer)
        };
        let result = plan_and_change(backend, target, level, yes, false, &mut ask);
        (result, questions)
    }

    #[test]
    fn rp_change_asks_before_any_change_request_is_sent() {
        let target = CredProtectTarget::Rp("ssh:".to_string());

        // The listing comes first, then the question, then (only if accepted) the change.
        let mut backend = FakeBackend::new(&[3, 3]);
        let (result, questions) = run_plan(&mut backend, &target, 1, false, false);
        assert!(error_text(result.map(|_| ())).contains("Cancelled"));
        assert_eq!(questions.len(), 1);
        assert_eq!(
            *backend.calls.borrow(),
            vec!["list_rp ssh:", "confirm"],
            "no change was sent"
        );

        let mut backend = FakeBackend::new(&[3, 3]);
        let (result, questions) = run_plan(&mut backend, &target, 1, false, true);
        let (_, changes) = result.expect("accepted");
        assert_eq!(questions.len(), 1);
        assert_eq!(
            *backend.calls.borrow(),
            vec!["list_rp ssh:", "confirm", "change 1 x2"],
            "the question comes before the change"
        );
        assert_eq!(changes.expect("changed").len(), 2);

        // The question names the level, the RP, the count and the device.
        let question = &questions[0];
        assert!(question.contains("userVerificationOptional"), "{question}");
        assert!(question.contains("2 credential(s)"), "{question}");
        assert!(question.contains("'ssh:'"), "{question}");
        assert!(question.contains("device index 7 (test)"), "{question}");
    }

    #[test]
    fn yes_skips_the_question_and_raising_never_asks() {
        let rp = CredProtectTarget::Rp("ssh:".to_string());

        let mut backend = FakeBackend::new(&[3]);
        let (result, questions) = run_plan(&mut backend, &rp, 1, true, false);
        result.expect("--yes lowers without asking");
        assert!(questions.is_empty());
        assert_eq!(*backend.calls.borrow(), vec!["list_rp ssh:", "change 1 x1"]);

        let mut backend = FakeBackend::new(&[1, 2]);
        let (result, questions) = run_plan(&mut backend, &rp, 3, false, false);
        result.expect("raising needs no confirmation");
        assert!(questions.is_empty());
        assert_eq!(*backend.calls.borrow(), vec!["list_rp ssh:", "change 3 x2"]);
    }

    #[test]
    fn nothing_is_sent_when_every_credential_already_has_the_level() {
        let rp = CredProtectTarget::Rp("ssh:".to_string());
        let mut backend = FakeBackend::new(&[1, 1]);
        let (result, questions) = run_plan(&mut backend, &rp, 1, false, true);
        let (listing, changes) = result.expect("ok");
        assert_eq!(listing.len(), 2);
        assert!(changes.is_none());
        assert!(questions.is_empty());
        assert_eq!(*backend.calls.borrow(), vec!["list_rp ssh:"]);
    }

    #[test]
    fn id_change_looks_up_and_shows_the_credential_and_confirms_when_lowering() {
        let backend_template = FakeBackend::new(&[3]);
        let id = backend_template.credentials[0].id.clone();
        let target = CredProtectTarget::Credential(id);

        let mut backend = FakeBackend::new(&[3]);
        let (result, questions) = run_plan(&mut backend, &target, 1, false, false);
        assert!(error_text(result.map(|_| ())).contains("Cancelled"));
        assert_eq!(
            *backend.calls.borrow(),
            vec!["find", "confirm"],
            "looked up, asked, never changed"
        );
        let question = &questions[0];
        assert!(question.contains("RP 'ssh:'"), "{question}");
        assert!(question.contains("key-0"), "{question}");
        assert!(question.contains("device index 7 (test)"), "{question}");

        // Accepted: lookup, then the change.
        let mut backend = FakeBackend::new(&[3]);
        let (result, _) = run_plan(&mut backend, &target, 1, false, true);
        let (listing, changes) = result.expect("accepted");
        assert_eq!(
            *backend.calls.borrow(),
            vec!["find", "confirm", "change 1 x1"]
        );
        assert_eq!(listing[0].rp_id, "ssh:");
        assert_eq!(changes.unwrap()[0].previous, 3);

        // --yes skips the question; raising never asks.
        let mut backend = FakeBackend::new(&[3]);
        let (result, questions) = run_plan(&mut backend, &target, 1, true, false);
        result.expect("--yes");
        assert!(questions.is_empty());
        let mut backend = FakeBackend::new(&[1]);
        let target = CredProtectTarget::Credential(backend.credentials[0].id.clone());
        let (result, questions) = run_plan(&mut backend, &target, 3, false, false);
        result.expect("raise");
        assert!(questions.is_empty());

        // Unknown credential: fails at the lookup.
        let mut backend = FakeBackend::new(&[3]);
        let target = CredProtectTarget::Credential(vec![9; 32]);
        let (result, questions) = run_plan(&mut backend, &target, 1, false, true);
        assert!(error_text(result.map(|_| ())).contains("not found"));
        assert!(questions.is_empty());
        assert_eq!(*backend.calls.borrow(), vec!["find"]);
    }

    #[test]
    fn a_failed_change_tells_the_user_to_verify_the_state() {
        let rp = CredProtectTarget::Rp("ssh:".to_string());
        let mut backend = FakeBackend::new(&[3, 3]);
        backend.change_error = Some("Failed to change credProtect: CTAP status 0x7f".to_string());
        let (result, _) = run_plan(&mut backend, &rp, 1, true, true);
        let message = error_text(result.map(|_| ()));
        assert!(message.contains("0x7f"), "{message}");
        assert!(message.contains("passless client list"), "{message}");
        assert!(
            message.contains("rolled back only best effort"),
            "{message}"
        );
        assert!(message.contains("Git commit"), "{message}");
    }

    #[test]
    fn the_lowering_warning_is_plain_about_the_risks() {
        let warning = lowering_warning(1);
        assert!(warning.contains("user_verification_authentication = false"));
        assert!(warning.contains("silent signing"));
        assert!(warning.contains("hidraw"));
        assert!(warning.contains("always_uv = true"));
        assert!(warning.contains("no effect"));
    }

    #[test]
    fn json_output_needs_yes_wherever_a_question_could_be_asked() {
        let id = "ab".repeat(32);
        for (credential_id, rp, level, ok) in [
            (Some(id.as_str()), None, 1u8, false),
            (Some(id.as_str()), None, 2, false),
            (Some(id.as_str()), None, 3, true),
            (None, Some("ssh:"), 3, false),
            (None, Some("ssh:"), 1, false),
        ] {
            let result =
                parse_cred_protect_target(OutputFormat::Json, credential_id, rp, level, false);
            assert_eq!(result.is_ok(), ok, "{credential_id:?} {rp:?} level {level}");
            assert!(
                parse_cred_protect_target(OutputFormat::Json, credential_id, rp, level, true)
                    .is_ok()
            );
        }
    }

    #[test]
    fn rejected_status_codes_have_specific_messages() {
        use soft_fido2::StatusCode;

        let text = |status: StatusCode| {
            set_cred_protect_error(&soft_fido2::Error::CtapError(status as u8))
        };
        assert!(text(StatusCode::OperationDenied).contains("denied, closed or timed out"));
        assert!(text(StatusCode::NotAllowed).contains("PASSLESS_INTERACTION_MODE=automatic"));
    }
}
