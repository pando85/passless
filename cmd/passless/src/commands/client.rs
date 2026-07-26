//! FIDO2 Client Management Commands

use crate::authenticator::{CMD_PASSLESS_RESET_UV_RETRIES, RESET_UV_RETRIES_SUBCOMMAND};

use std::collections::HashMap;

use passless_core::{OutputFormat, Result};

use rpassword::read_password;

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

            fallback_to_pin_auth(transport, output, uv_error)
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
                println!("Enter PIN: ");
            }

            let pin = read_password()
                .map_err(|e| passless_core::Error::Other(format!("Failed to read PIN: {:?}", e)))?;

            if pin.is_empty() {
                return Err(passless_core::Error::Other(
                    "PIN is required for credential management on this authenticator".to_string(),
                ));
            }

            if output == OutputFormat::Plain {
                println!();
            }

            Client::get_pin_token_for_credential_management(transport, &pin, PinProtocol::V2)
                .map_err(|e| {
                    passless_core::Error::Other(format!(
                        "PIN authentication failed: {:?}. UV was also unavailable: {:?}",
                        e, uv_error
                    ))
                })
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

    // Send command 0x42 with the CBOR payload
    let response = transport
        .send_ctap_command(CMD_PASSLESS_RESET_UV_RETRIES, &payload_bytes, 30000)
        .map_err(|e| passless_core::Error::Other(format!("UV retry reset failed: {:?}", e)))?;

    let success = response == [0xa0] || response.first() == Some(&0x00);
    if !success {
        return Err(passless_core::Error::Other(format!(
            "UV retry reset failed with status: 0x{:02x}",
            response.first().copied().unwrap_or(0xff)
        )));
    }

    // Parse the UV retries count from the response if available
    let uv_retries_count = if response.len() > 1 {
        if let Ok(soft_fido2_ctap::cbor::Value::Map(map)) =
            soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&response[1..])
        {
            map.iter()
                .find(|(k, _)| *k == soft_fido2_ctap::cbor::Value::Integer(1))
                .and_then(|(_, v)| {
                    if let soft_fido2_ctap::cbor::Value::Integer(n) = v {
                        Some(*n as u8)
                    } else {
                        None
                    }
                })
        } else {
            None
        }
    } else {
        None
    };

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
