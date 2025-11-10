use crate::storage::CredentialStorage;

use keylib::Result;
use keylib::credential::RelyingParty;

use std::sync::{Mutex, OnceLock};

use log::{debug, info, trace};

/// Maximum timeout for RP iteration (milliseconds) - matching Zig example
const MAX_TIMEOUT_MS: i64 = 1000;

/// Static state for credential management
static CRED_MGMT_STATE: OnceLock<Mutex<CredMgmtStaticState>> = OnceLock::new();

/// Static state structure for credential management
struct CredMgmtStaticState {
    /// Timestamp when iteration started (milliseconds)
    i: i64,
    /// Optional list of relying parties being iterated
    rps: Option<Vec<RelyingParty>>,
}

impl CredMgmtStaticState {
    fn new() -> Self {
        Self { i: 0, rps: None }
    }

    /// Deinitialize RPs
    fn deinit_rps(&mut self) {
        if let Some(mut _rps) = self.rps.take() {
            _rps.clear();
        }
        self.rps = None;
        debug!("RP iteration state cleared");
    }

    /// Get next RP from the iteration (equivalent to Zig getRp)
    fn get_rp(&mut self) -> Option<RelyingParty> {
        // Check if we have RPs
        self.rps.as_ref()?;

        // Check timeout
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        if now - self.i > MAX_TIMEOUT_MS {
            info!("RP iteration timed out after {}ms", MAX_TIMEOUT_MS);
            self.deinit_rps();
            return None;
        }

        // Get the RPs vector
        if let Some(ref mut rps) = self.rps {
            if rps.is_empty() {
                self.deinit_rps();
                return None;
            }

            // Remove first element (equivalent to swapRemove(0))
            let rp = rps.remove(0);
            debug!("Retrieved RP: {}", rp.id);

            // Clean up if empty
            if rps.is_empty() {
                self.deinit_rps();
            }

            Some(rp)
        } else {
            None
        }
    }

    /// Initialize RP iteration with a list of relying parties
    fn init_rps(&mut self, rps: Vec<RelyingParty>) {
        self.i = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        self.rps = Some(rps);
        info!("RP iteration initialized with timestamp: {}", self.i);
    }
}

/// Get or initialize the static state
fn get_state() -> &'static Mutex<CredMgmtStaticState> {
    CRED_MGMT_STATE.get_or_init(|| Mutex::new(CredMgmtStaticState::new()))
}

/// Authenticator Credential Management function
///
/// This is the Rust equivalent of the Zig `authenticatorCredentialManagement` function.
/// It handles commands 0x0a and 0x41 with static state management.
///
/// # Commands
///
/// - **0x0a**: Standard CTAP2 CredentialManagement command
/// - **0x41**: Custom credential management command (same implementation)
///
/// # Arguments
///
/// * `request` - The CTAP request bytes (CBOR-encoded with subCommand parameter)
/// * `storage` - Storage backend for accessing credentials
///
/// # Returns
///
/// Result containing the CBOR-encoded response data or an error
///
/// # State Management
///
/// This function uses static state (similar to Zig) to maintain RP iteration
/// across multiple command invocations. The state includes:
/// - Timestamp of iteration start
/// - List of RPs being iterated
/// - Automatic cleanup after timeout (1000ms)
///
/// # CBOR Format
///
/// Request: { 0x01: subCommand (u8), ... }
/// Response (enumerateRPsBegin/Next): { 0x03: { "id": rp_id }, 0x04: rp_id_hash, 0x05: totalRPs }
/// Response (getCredsMetadata): { 0x01: existingResidentCredentialsCount, 0x02: maxPossibleRemainingResidentCredentialsCount }
pub fn authenticator_credential_management<S: CredentialStorage>(
    request: &[u8],
    storage: &S,
) -> Result<Vec<u8>> {
    use serde_cbor::Value as CborValue;
    use std::collections::BTreeMap;

    // Log the full request for debugging
    info!(
        "Processing credential management request: {} bytes",
        request.len()
    );
    debug!("Request hex: {:02x?}", request);

    // The request buffer may have padding/trailing zeros
    // We need to find where the CBOR data actually ends
    // CBOR map starts with 0xa3 (map with 3 items) for our case
    // Let's try to parse it manually or find the end

    // Quick workaround: try different lengths until one works
    let mut request_value: Option<CborValue> = None;
    let mut cbor_len = request.len();

    // Try parsing with decreasing lengths to find where CBOR actually ends
    while cbor_len > 0 && request_value.is_none() {
        match serde_cbor::from_slice::<CborValue>(&request[..cbor_len]) {
            Ok(val) => {
                info!("Successfully parsed CBOR value with {} bytes", cbor_len);
                request_value = Some(val);
                break;
            }
            Err(_e) if cbor_len > 40 => {
                // Try shorter length
                cbor_len -= 1;
            }
            Err(e) => {
                log::error!("Failed to parse CBOR request even with trimming: {}", e);
                log::error!("Request bytes: {:02x?}", request);
                return Err(keylib::Error::Other);
            }
        }
    }

    let request_value = match request_value {
        Some(val) => val,
        None => {
            log::error!("Could not parse CBOR request at any length");
            return Err(keylib::Error::Other);
        }
    };

    // Extract map from the value
    let request_map = match request_value {
        CborValue::Map(map) => map,
        other => {
            log::error!("Expected CBOR map, got: {:?}", other);
            return Err(keylib::Error::Other);
        }
    };

    info!("Parsed CBOR map with {} keys", request_map.len());

    // Log all keys in the request
    for (key, value) in &request_map {
        debug!("Request key {:?}: {:?}", key, value);
    }

    // Get subCommand parameter (key 0x01)
    let sub_command = match request_map.get(&CborValue::Integer(0x01)) {
        Some(CborValue::Integer(cmd)) => *cmd as u8,
        other => {
            log::error!("Missing or invalid subCommand parameter: {:?}", other);
            return Err(keylib::Error::Other);
        }
    };

    info!("Credential management subCommand: 0x{:02x}", sub_command);

    let state = get_state();
    let mut state_guard = state.lock().unwrap();

    match sub_command {
        0x01 => {
            // getCredsMetadata - Get count of credentials
            let count = storage.get_relying_parties()?.len();
            info!("Credentials metadata: {} RPs", count);

            let mut response = BTreeMap::new();
            response.insert(CborValue::Integer(0x01), CborValue::Integer(count as i128)); // existingResidentCredentialsCount
            response.insert(CborValue::Integer(0x02), CborValue::Integer(9999)); // maxPossibleRemainingResidentCredentialsCount (arbitrary)

            let response_data = serde_cbor::to_vec(&CborValue::Map(response)).map_err(|e| {
                log::error!("Failed to encode CBOR response: {}", e);
                keylib::Error::Other
            })?;

            debug!("Returning metadata response: {} bytes", response_data.len());
            trace!("Response hex: {:02x?}", response_data);
            Ok(response_data)
        }
        0x02 => {
            let rps = storage.get_relying_parties()?;

            let total_rps = rps.len();
            info!("Starting RP enumeration with {} RPs", total_rps);
            state_guard.init_rps(rps);

            // Get first RP
            if let Some(rp) = state_guard.get_rp() {
                info!("Returning first RP: {}", rp.id);

                // Build CBOR response: { 0x03: { "id": rp_id }, 0x04: rp_id_hash, 0x05: totalRPs }
                let mut rp_map = BTreeMap::new();
                rp_map.insert(
                    CborValue::Text("id".to_string()),
                    CborValue::Text(rp.id.clone()),
                );

                let mut response = BTreeMap::new();
                response.insert(CborValue::Integer(0x03), CborValue::Map(rp_map)); // rp
                response.insert(CborValue::Integer(0x04), CborValue::Bytes(vec![0u8; 32])); // rpIDHash (dummy for now)
                response.insert(
                    CborValue::Integer(0x05),
                    CborValue::Integer(total_rps as i128),
                ); // totalRPs

                let response_data = serde_cbor::to_vec(&CborValue::Map(response)).map_err(|e| {
                    log::error!("Failed to encode CBOR response: {}", e);
                    keylib::Error::Other
                })?;

                debug!("Returning RP response: {} bytes", response_data.len());
                trace!("Response hex: {:02x?}", response_data);
                Ok(response_data)
            } else {
                info!("No RPs to enumerate");
                Err(keylib::Error::DoesNotExist)
            }
        }
        0x03 => {
            // enumerateRPsGetNextRP - Get next RP
            if let Some(rp) = state_guard.get_rp() {
                info!("Returning next RP: {}", rp.id);

                // Build CBOR response
                let mut rp_map = BTreeMap::new();
                rp_map.insert(
                    CborValue::Text("id".to_string()),
                    CborValue::Text(rp.id.clone()),
                );

                let mut response = BTreeMap::new();
                response.insert(CborValue::Integer(0x03), CborValue::Map(rp_map)); // rp
                response.insert(CborValue::Integer(0x04), CborValue::Bytes(vec![0u8; 32])); // rpIDHash (dummy for now)

                let response_data = serde_cbor::to_vec(&CborValue::Map(response)).map_err(|e| {
                    log::error!("Failed to encode CBOR response: {}", e);
                    keylib::Error::Other
                })?;

                info!("Returning next RP response: {} bytes", response_data.len());
                trace!("Response hex: {:02x?}", response_data);
                Ok(response_data)
            } else {
                info!("No more RPs to enumerate");
                Err(keylib::Error::DoesNotExist)
            }
        }
        _ => {
            info!(
                "Unsupported credential management subCommand: 0x{:02x}",
                sub_command
            );
            Err(keylib::Error::Other)
        }
    }
}
