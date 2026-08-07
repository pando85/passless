use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use passless_core::agent::protocol::IntentAction;
use passless_core::agent::{
    AgentAuthorization, CredentialRef, EndpointId, PolicyDigest, PolicyGenerationId,
    PrincipalSessionId, ProfileId, UserPresenceSource, UserVerificationSource,
};

use serde_cbor as cbor;
use soft_fido2_transport::{Cmd, CommandHandler};

use super::audit::AuditGate;
use super::audit_events::{
    AuditAction, CeremonyFailureBuilder, CeremonyStartBuilder, CeremonySuccessBuilder,
    PolicyAllowBuilder, PolicyDenyBuilder, PolicyDenyReason, PromptApproveBuilder,
    PromptDenyBuilder, PromptDisplayBuilder, PromptErrorBuilder, PromptTimeoutBuilder,
};
use super::intent::ProcessIdentityDigest;
use super::interaction::{AgentInteractionManager, InteractionTokenGuard};
use super::policy_engine::{
    AuthorizationRequest, CeremonyTuple, PolicyRuntime, ReasonCode, TrustedApproval,
};
use super::prompt::{PromptAction, PromptMode, PromptRequest};
use super::storage::CeremonyScope;

#[cfg(test)]
use crate::agent::ceremony_observer::{CeremonyObservation, TerminalResult, TestObserver};
use crate::agent::grant::CeremonyId;
use crate::agent::prompt::PromptHandle;

const CMD_MAKE_CREDENTIAL: u8 = 0x01;
const CMD_GET_ASSERTION: u8 = 0x02;
const CMD_GET_INFO: u8 = 0x04;
const CMD_CLIENT_PIN: u8 = 0x06;
const CMD_RESET: u8 = 0x07;
const CMD_CREDENTIAL_MGMT: u8 = 0x0A;
const CMD_SELECTION: u8 = 0x0B;
const CMD_GET_NEXT_ASSERTION: u8 = 0x08;
const CMD_VENDOR_FIRST: u8 = 0x40;
const CMD_VENDOR_LAST: u8 = 0xBF;

const MC_KEY_CLIENT_DATA_HASH: u64 = 0x01;
const MC_KEY_RP: u64 = 0x02;
const MC_KEY_USER: u64 = 0x03;
const MC_KEY_PUB_KEY_CRED_PARAMS: u64 = 0x04;
const MC_KEY_EXCLUDE_LIST: u64 = 0x05;
const MC_KEY_EXTENSIONS: u64 = 0x06;
const MC_KEY_OPTIONS: u64 = 0x07;
const MC_KEY_PIN_UV_AUTH_PARAM: u64 = 0x08;
const MC_KEY_ENTERPRISE_ATTESTATION: u64 = 0x09;

const GA_KEY_RP_ID: u64 = 0x01;
const GA_KEY_CLIENT_DATA_HASH: u64 = 0x02;
const GA_KEY_ALLOW_LIST: u64 = 0x03;
const GA_KEY_EXTENSIONS: u64 = 0x04;
const GA_KEY_OPTIONS: u64 = 0x05;
const GA_KEY_PIN_UV_AUTH_PARAM: u64 = 0x06;
const GA_KEY_PIN_UV_AUTH_PROTOCOL: u64 = 0x07;

const RESP_KEY_FORMAT: u64 = 0x01;
const RESP_KEY_AUTH_DATA: u64 = 0x02;
const RESP_KEY_ATT_STMT: u64 = 0x03;
const RESP_KEY_CREDENTIAL: u64 = 0x01;
const RESP_KEY_SIGNATURE: u64 = 0x03;

const DESCRIPTOR_KEY_ID: &str = "id";
const RP_KEY_ID: &str = "id";

const CTAP_OK: u8 = 0x00;
const CTAP_ERR_OPERATION_DENIED: u8 = 0x27;

const AUTH_DATA_MIN_LEN: usize = 37;
const AUTH_DATA_FLAGS_OFFSET: usize = 32;
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

pub const MAX_CREDENTIAL_ID_SIZE: usize = 256;
pub const MAX_DESCRIPTOR_COUNT: usize = 16;
pub const MAX_RP_ID_LEN: usize = 253;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMakeCredential {
    pub rp_id: String,
    pub require_uv: bool,
    pub exclude_refs: Vec<CredentialRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedGetAssertion {
    pub rp_id: String,
    pub require_uv: bool,
    pub allow_refs: Vec<CredentialRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedCeremonyRequest {
    MakeCredential(ParsedMakeCredential),
    GetAssertion(ParsedGetAssertion),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedMakeCredentialResponse {
    pub auth_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedGetAssertionResponse {
    pub auth_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ParsedCeremonyResponse {
    MakeCredential(ParsedMakeCredentialResponse),
    GetAssertion(ParsedGetAssertionResponse),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandClass {
    Ceremony,
    SafeNonCeremony,
    Denied,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    MakeCredential,
    GetAssertion,
    GetNextAssertion,
    GetInfo,
    ClientPin,
    Reset,
    CredentialMgmt,
    Selection,
    Vendor(u8),
    Unknown(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CeremonyError {
    EmptyInput,
    CommandTooShort,
    InvalidCbor,
    DuplicateKey,
    NotAMap,
    WrongCommand,
    MissingField(&'static str),
    InvalidFieldType(&'static str),
    RpIdEmpty,
    RpIdTooLong,
    RpIdInvalid,
    CredentialIdTooLarge,
    TooManyDescriptors,
    AuthDataTooShort,
    UpNotSet,
    UvNotSet,
    MalformedResponse,
    NonZeroStatus,
}

impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "empty input"),
            Self::CommandTooShort => write!(f, "command too short"),
            Self::InvalidCbor => write!(f, "invalid CBOR encoding"),
            Self::DuplicateKey => write!(f, "duplicate key in CBOR map"),
            Self::NotAMap => write!(f, "expected CBOR map"),
            Self::WrongCommand => write!(f, "wrong command for ceremony"),
            Self::MissingField(name) => write!(f, "missing required field: {}", name),
            Self::InvalidFieldType(name) => write!(f, "invalid field type: {}", name),
            Self::RpIdEmpty => write!(f, "RP ID is empty"),
            Self::RpIdTooLong => write!(f, "RP ID exceeds maximum length"),
            Self::RpIdInvalid => write!(f, "RP ID is not a valid domain"),
            Self::CredentialIdTooLarge => write!(f, "credential ID exceeds maximum size"),
            Self::TooManyDescriptors => write!(f, "too many credential descriptors"),
            Self::AuthDataTooShort => write!(f, "authenticator data too short"),
            Self::UpNotSet => write!(f, "UP flag not set"),
            Self::UvNotSet => write!(f, "UV flag not set"),
            Self::MalformedResponse => write!(f, "malformed response"),
            Self::NonZeroStatus => write!(f, "non-zero CTAP status code"),
        }
    }
}

impl std::error::Error for CeremonyError {}

fn decode_command(cmd: u8) -> Command {
    match cmd {
        CMD_MAKE_CREDENTIAL => Command::MakeCredential,
        CMD_GET_ASSERTION => Command::GetAssertion,
        CMD_GET_INFO => Command::GetInfo,
        CMD_CLIENT_PIN => Command::ClientPin,
        CMD_RESET => Command::Reset,
        CMD_CREDENTIAL_MGMT => Command::CredentialMgmt,
        CMD_SELECTION => Command::Selection,
        CMD_GET_NEXT_ASSERTION => Command::GetNextAssertion,
        CMD_VENDOR_FIRST..=CMD_VENDOR_LAST => Command::Vendor(cmd),
        _ => Command::Unknown(cmd),
    }
}

pub fn classify_command(cmd: u8) -> CommandClass {
    match decode_command(cmd) {
        Command::MakeCredential | Command::GetAssertion => CommandClass::Ceremony,
        Command::GetInfo | Command::ClientPin | Command::Selection => CommandClass::SafeNonCeremony,
        Command::CredentialMgmt | Command::Reset | Command::GetNextAssertion => {
            CommandClass::Denied
        }
        Command::Vendor(_) => CommandClass::Denied,
        Command::Unknown(_) => CommandClass::Unknown,
    }
}

#[cfg(test)]
pub fn parse_command(input: &[u8]) -> Result<Command, CeremonyError> {
    if input.is_empty() {
        return Err(CeremonyError::EmptyInput);
    }
    Ok(decode_command(input[0]))
}

pub fn parse_ceremony_request(raw: &[u8]) -> Result<ParsedCeremonyRequest, CeremonyError> {
    if raw.is_empty() {
        return Err(CeremonyError::EmptyInput);
    }
    if raw.len() < 2 {
        return Err(CeremonyError::CommandTooShort);
    }

    let cmd = raw[0];
    let cbor_bytes = &raw[1..];

    match decode_command(cmd) {
        Command::MakeCredential => {
            let mc = parse_make_credential(cbor_bytes)?;
            Ok(ParsedCeremonyRequest::MakeCredential(mc))
        }
        Command::GetAssertion => {
            let ga = parse_get_assertion(cbor_bytes)?;
            Ok(ParsedCeremonyRequest::GetAssertion(ga))
        }
        _ => Err(CeremonyError::WrongCommand),
    }
}

fn parse_make_credential(data: &[u8]) -> Result<ParsedMakeCredential, CeremonyError> {
    let value: cbor::Value = cbor::from_slice(data).map_err(|_| CeremonyError::InvalidCbor)?;
    let map = match &value {
        cbor::Value::Map(m) => m,
        _ => return Err(CeremonyError::NotAMap),
    };

    if has_duplicate_keys(data)? {
        return Err(CeremonyError::DuplicateKey);
    }

    let rp_entry = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(MC_KEY_RP as i128))
        .ok_or(CeremonyError::MissingField("rp"))?;
    let rp_id = parse_rp_entity(rp_entry)?;

    let _ = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(MC_KEY_CLIENT_DATA_HASH as i128))
        .ok_or(CeremonyError::MissingField("clientDataHash"))?;

    let options_uv = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(MC_KEY_OPTIONS as i128))
        .map(|(_, v)| parse_options_uv(v))
        .transpose()?
        .unwrap_or(false);

    let _ = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(MC_KEY_PUB_KEY_CRED_PARAMS as i128))
        .ok_or(CeremonyError::MissingField("pubKeyCredParams"))?;

    let exclude_refs = match map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(MC_KEY_EXCLUDE_LIST as i128))
    {
        Some((_, cbor::Value::Array(arr))) => {
            if arr.len() > MAX_DESCRIPTOR_COUNT {
                return Err(CeremonyError::TooManyDescriptors);
            }
            parse_descriptor_list(arr)?
        }
        Some(_) => return Err(CeremonyError::InvalidFieldType("excludeList")),
        None => Vec::new(),
    };

    if let Some((_, v)) = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(MC_KEY_EXTENSIONS as i128))
        && !matches!(v, cbor::Value::Map(_))
    {
        return Err(CeremonyError::InvalidFieldType("extensions"));
    }

    if let Some((_, v)) = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(MC_KEY_USER as i128))
        && !matches!(v, cbor::Value::Map(_))
    {
        return Err(CeremonyError::InvalidFieldType("user"));
    }

    if let Some((_, v)) = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(MC_KEY_PIN_UV_AUTH_PARAM as i128))
        && !matches!(v, cbor::Value::Bytes(_))
    {
        return Err(CeremonyError::InvalidFieldType("pinUvAuthParam"));
    }

    if let Some((_, v)) = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(MC_KEY_ENTERPRISE_ATTESTATION as i128))
        && !matches!(v, cbor::Value::Integer(_))
    {
        return Err(CeremonyError::InvalidFieldType("enterpriseAttestation"));
    }

    Ok(ParsedMakeCredential {
        rp_id,
        require_uv: options_uv,
        exclude_refs,
    })
}

fn parse_get_assertion(data: &[u8]) -> Result<ParsedGetAssertion, CeremonyError> {
    let value: cbor::Value = cbor::from_slice(data).map_err(|_| CeremonyError::InvalidCbor)?;
    let map = match &value {
        cbor::Value::Map(m) => m,
        _ => return Err(CeremonyError::NotAMap),
    };

    if has_duplicate_keys(data)? {
        return Err(CeremonyError::DuplicateKey);
    }

    let rp_id = match map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(GA_KEY_RP_ID as i128))
    {
        Some((_, cbor::Value::Text(s))) => validate_rp_id(s)?,
        Some(_) => return Err(CeremonyError::InvalidFieldType("rpId")),
        None => return Err(CeremonyError::MissingField("rpId")),
    };

    let _ = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(GA_KEY_CLIENT_DATA_HASH as i128))
        .ok_or(CeremonyError::MissingField("clientDataHash"))?;

    let options_uv = match map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(GA_KEY_OPTIONS as i128))
    {
        Some((_, v)) => parse_options_uv(v)?,
        None => false,
    };

    let allow_refs = match map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(GA_KEY_ALLOW_LIST as i128))
    {
        Some((_, cbor::Value::Array(arr))) => {
            if arr.len() > MAX_DESCRIPTOR_COUNT {
                return Err(CeremonyError::TooManyDescriptors);
            }
            parse_descriptor_list(arr)?
        }
        Some(_) => return Err(CeremonyError::InvalidFieldType("allowList")),
        None => Vec::new(),
    };

    if let Some((_, v)) = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(GA_KEY_EXTENSIONS as i128))
        && !matches!(v, cbor::Value::Map(_))
    {
        return Err(CeremonyError::InvalidFieldType("extensions"));
    }

    if let Some((_, v)) = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(GA_KEY_PIN_UV_AUTH_PARAM as i128))
        && !matches!(v, cbor::Value::Bytes(_))
    {
        return Err(CeremonyError::InvalidFieldType("pinUvAuthParam"));
    }

    if let Some((_, v)) = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(GA_KEY_PIN_UV_AUTH_PROTOCOL as i128))
        && !matches!(v, cbor::Value::Integer(_))
    {
        return Err(CeremonyError::InvalidFieldType("pinUvAuthProtocol"));
    }

    Ok(ParsedGetAssertion {
        rp_id,
        require_uv: options_uv,
        allow_refs,
    })
}

pub fn parse_ceremony_response(
    cmd: u8,
    raw: &[u8],
    require_uv: bool,
) -> Result<ParsedCeremonyResponse, CeremonyError> {
    if raw.is_empty() {
        return Err(CeremonyError::EmptyInput);
    }

    let status = raw[0];
    if status != CTAP_OK {
        return Err(CeremonyError::NonZeroStatus);
    }

    let cbor_bytes = &raw[1..];

    match decode_command(cmd) {
        Command::MakeCredential => {
            let resp = parse_make_credential_response(cbor_bytes, require_uv)?;
            Ok(ParsedCeremonyResponse::MakeCredential(resp))
        }
        Command::GetAssertion => {
            let resp = parse_get_assertion_response(cbor_bytes, require_uv)?;
            Ok(ParsedCeremonyResponse::GetAssertion(resp))
        }
        _ => Err(CeremonyError::WrongCommand),
    }
}

fn parse_make_credential_response(
    data: &[u8],
    require_uv: bool,
) -> Result<ParsedMakeCredentialResponse, CeremonyError> {
    let value: cbor::Value = cbor::from_slice(data).map_err(|_| CeremonyError::InvalidCbor)?;
    let map = match &value {
        cbor::Value::Map(m) => m,
        _ => return Err(CeremonyError::MalformedResponse),
    };

    let auth_data = match map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(RESP_KEY_AUTH_DATA as i128))
    {
        Some((_, cbor::Value::Bytes(b))) => b.clone(),
        Some(_) => return Err(CeremonyError::MalformedResponse),
        None => return Err(CeremonyError::MalformedResponse),
    };

    let _ = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(RESP_KEY_FORMAT as i128))
        .ok_or(CeremonyError::MalformedResponse)?;

    let _ = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(RESP_KEY_ATT_STMT as i128))
        .ok_or(CeremonyError::MalformedResponse)?;

    verify_auth_data_flags(&auth_data, require_uv)?;

    Ok(ParsedMakeCredentialResponse { auth_data })
}

fn parse_get_assertion_response(
    data: &[u8],
    require_uv: bool,
) -> Result<ParsedGetAssertionResponse, CeremonyError> {
    let value: cbor::Value = cbor::from_slice(data).map_err(|_| CeremonyError::InvalidCbor)?;
    let map = match &value {
        cbor::Value::Map(m) => m,
        _ => return Err(CeremonyError::MalformedResponse),
    };

    let _ = map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(RESP_KEY_CREDENTIAL as i128))
        .ok_or(CeremonyError::MalformedResponse)?;

    let auth_data = match map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(RESP_KEY_AUTH_DATA as i128))
    {
        Some((_, cbor::Value::Bytes(b))) => b.clone(),
        Some(_) => return Err(CeremonyError::MalformedResponse),
        None => return Err(CeremonyError::MalformedResponse),
    };

    match map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(RESP_KEY_SIGNATURE as i128))
    {
        Some((_, cbor::Value::Bytes(_))) => {}
        _ => return Err(CeremonyError::MalformedResponse),
    }

    verify_auth_data_flags(&auth_data, require_uv)?;

    Ok(ParsedGetAssertionResponse { auth_data })
}

fn verify_auth_data_flags(auth_data: &[u8], require_uv: bool) -> Result<(), CeremonyError> {
    if auth_data.len() < AUTH_DATA_MIN_LEN {
        return Err(CeremonyError::AuthDataTooShort);
    }

    let flags = auth_data[AUTH_DATA_FLAGS_OFFSET];

    if flags & FLAG_UP == 0 {
        return Err(CeremonyError::UpNotSet);
    }

    if require_uv && flags & FLAG_UV == 0 {
        return Err(CeremonyError::UvNotSet);
    }

    Ok(())
}

fn parse_rp_entity(value: (&cbor::Value, &cbor::Value)) -> Result<String, CeremonyError> {
    match value.1 {
        cbor::Value::Map(m) => {
            let id = m
                .iter()
                .find(|(k, _)| **k == cbor::Value::Text(RP_KEY_ID.to_string()))
                .ok_or(CeremonyError::MissingField("rp.id"))?;
            match id.1 {
                cbor::Value::Text(s) => validate_rp_id(s),
                _ => Err(CeremonyError::InvalidFieldType("rp.id")),
            }
        }
        _ => Err(CeremonyError::InvalidFieldType("rp")),
    }
}

fn validate_rp_id(raw: &str) -> Result<String, CeremonyError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CeremonyError::RpIdEmpty);
    }
    if trimmed.len() > MAX_RP_ID_LEN {
        return Err(CeremonyError::RpIdTooLong);
    }
    let normalized = trimmed.to_ascii_lowercase();

    if normalized.contains("://")
        || normalized.contains('/')
        || normalized.contains(':')
        || normalized.starts_with('*')
        || normalized.ends_with('.')
    {
        return Err(CeremonyError::RpIdInvalid);
    }

    if !normalized.contains('.') {
        return Err(CeremonyError::RpIdInvalid);
    }

    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(CeremonyError::RpIdInvalid);
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(CeremonyError::RpIdInvalid);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(CeremonyError::RpIdInvalid);
        }
    }

    Ok(normalized)
}

fn parse_options_uv(value: &cbor::Value) -> Result<bool, CeremonyError> {
    match value {
        cbor::Value::Map(m) => {
            for (k, v) in m {
                if let (cbor::Value::Text(key), cbor::Value::Bool(val)) = (k, v)
                    && key == "uv"
                {
                    return Ok(*val);
                }
            }
            Ok(false)
        }
        _ => Err(CeremonyError::InvalidFieldType("options")),
    }
}

fn parse_descriptor_list(descriptors: &[cbor::Value]) -> Result<Vec<CredentialRef>, CeremonyError> {
    let mut refs = Vec::with_capacity(descriptors.len());
    for desc in descriptors {
        let cred_ref = parse_descriptor(desc)?;
        refs.push(cred_ref);
    }
    Ok(refs)
}

fn parse_descriptor(value: &cbor::Value) -> Result<CredentialRef, CeremonyError> {
    match value {
        cbor::Value::Map(m) => {
            let id = m
                .iter()
                .find(|(k, _)| **k == cbor::Value::Text(DESCRIPTOR_KEY_ID.to_string()))
                .ok_or(CeremonyError::MissingField("descriptor.id"))?;
            match &id.1 {
                cbor::Value::Bytes(b) => parse_credential_id(b),
                _ => Err(CeremonyError::InvalidFieldType("descriptor.id")),
            }
        }
        _ => Err(CeremonyError::InvalidFieldType("descriptor")),
    }
}

fn parse_credential_id(bytes: &[u8]) -> Result<CredentialRef, CeremonyError> {
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_ID_SIZE {
        return Err(CeremonyError::CredentialIdTooLarge);
    }
    Ok(CredentialRef::with_default_domain(bytes))
}

fn has_duplicate_keys(data: &[u8]) -> Result<bool, CeremonyError> {
    if data.is_empty() {
        return Ok(false);
    }

    let initial = data[0];
    let (major_type, info) = (initial >> 5, initial & 0x1f);

    if major_type != 5 {
        return Ok(false);
    }

    let count = match info {
        0..=23 => info as usize,
        24 => {
            if data.len() < 2 {
                return Err(CeremonyError::InvalidCbor);
            }
            data[1] as usize
        }
        25 => {
            if data.len() < 3 {
                return Err(CeremonyError::InvalidCbor);
            }
            u16::from_be_bytes([data[1], data[2]]) as usize
        }
        _ => return Err(CeremonyError::InvalidCbor),
    };

    let mut pos = match info {
        0..=23 => 1,
        24 => 2,
        25 => 3,
        _ => return Err(CeremonyError::InvalidCbor),
    };

    let mut seen = std::collections::HashSet::new();

    for _ in 0..count {
        if pos >= data.len() {
            return Err(CeremonyError::InvalidCbor);
        }
        let key_start = pos;
        skip_cbor_value(data, &mut pos)?;
        let key_bytes = &data[key_start..pos];

        if !seen.insert(key_bytes.to_vec()) {
            return Ok(true);
        }

        if pos >= data.len() {
            return Err(CeremonyError::InvalidCbor);
        }
        skip_cbor_value(data, &mut pos)?;
    }

    Ok(false)
}

fn skip_cbor_value(data: &[u8], pos: &mut usize) -> Result<(), CeremonyError> {
    if *pos >= data.len() {
        return Err(CeremonyError::InvalidCbor);
    }

    let initial = data[*pos];
    let major_type = initial >> 5;
    let info = initial & 0x1f;
    *pos += 1;

    let additional = match info {
        0..=23 => 0usize,
        24 => {
            if *pos >= data.len() {
                return Err(CeremonyError::InvalidCbor);
            }
            *pos += 1;
            0
        }
        25 => {
            if *pos + 1 >= data.len() {
                return Err(CeremonyError::InvalidCbor);
            }
            *pos += 2;
            0
        }
        26 => {
            if *pos + 3 >= data.len() {
                return Err(CeremonyError::InvalidCbor);
            }
            *pos += 4;
            0
        }
        27 => {
            if *pos + 7 >= data.len() {
                return Err(CeremonyError::InvalidCbor);
            }
            *pos += 8;
            0
        }
        31 => 0,
        _ => {
            return Err(CeremonyError::InvalidCbor);
        }
    };
    let _ = additional;

    match major_type {
        0 | 1 => {}
        2 | 3 => {
            let len = match info {
                0..=23 => info as usize,
                24 => {
                    if *pos > data.len() {
                        return Err(CeremonyError::InvalidCbor);
                    }
                    data[*pos - 1] as usize
                }
                25 => {
                    if *pos > data.len() {
                        return Err(CeremonyError::InvalidCbor);
                    }
                    u16::from_be_bytes([data[*pos - 2], data[*pos - 1]]) as usize
                }
                26 => {
                    if *pos > data.len() {
                        return Err(CeremonyError::InvalidCbor);
                    }
                    u32::from_be_bytes([
                        data[*pos - 4],
                        data[*pos - 3],
                        data[*pos - 2],
                        data[*pos - 1],
                    ]) as usize
                }
                27 => {
                    if *pos > data.len() {
                        return Err(CeremonyError::InvalidCbor);
                    }
                    u64::from_be_bytes([
                        data[*pos - 8],
                        data[*pos - 7],
                        data[*pos - 6],
                        data[*pos - 5],
                        data[*pos - 4],
                        data[*pos - 3],
                        data[*pos - 2],
                        data[*pos - 1],
                    ]) as usize
                }
                31 => {
                    loop {
                        if *pos >= data.len() {
                            return Err(CeremonyError::InvalidCbor);
                        }
                        if data[*pos] == 0xff {
                            *pos += 1;
                            break;
                        }
                        skip_cbor_value(data, pos)?;
                    }
                    return Ok(());
                }
                _ => return Err(CeremonyError::InvalidCbor),
            };
            if *pos + len > data.len() {
                return Err(CeremonyError::InvalidCbor);
            }
            *pos += len;
        }
        4 => {
            let count = match info {
                0..=23 => info as usize,
                24 => data[*pos - 1] as usize,
                25 => u16::from_be_bytes([data[*pos - 2], data[*pos - 1]]) as usize,
                26 => u32::from_be_bytes([
                    data[*pos - 4],
                    data[*pos - 3],
                    data[*pos - 2],
                    data[*pos - 1],
                ]) as usize,
                27 => u64::from_be_bytes([
                    data[*pos - 8],
                    data[*pos - 7],
                    data[*pos - 6],
                    data[*pos - 5],
                    data[*pos - 4],
                    data[*pos - 3],
                    data[*pos - 2],
                    data[*pos - 1],
                ]) as usize,
                31 => {
                    loop {
                        if *pos >= data.len() {
                            return Err(CeremonyError::InvalidCbor);
                        }
                        if data[*pos] == 0xff {
                            *pos += 1;
                            break;
                        }
                        skip_cbor_value(data, pos)?;
                    }
                    return Ok(());
                }
                _ => return Err(CeremonyError::InvalidCbor),
            };
            for _ in 0..count {
                skip_cbor_value(data, pos)?;
            }
        }
        5 => {
            let count = match info {
                0..=23 => info as usize,
                24 => data[*pos - 1] as usize,
                25 => u16::from_be_bytes([data[*pos - 2], data[*pos - 1]]) as usize,
                26 => u32::from_be_bytes([
                    data[*pos - 4],
                    data[*pos - 3],
                    data[*pos - 2],
                    data[*pos - 1],
                ]) as usize,
                27 => u64::from_be_bytes([
                    data[*pos - 8],
                    data[*pos - 7],
                    data[*pos - 6],
                    data[*pos - 5],
                    data[*pos - 4],
                    data[*pos - 3],
                    data[*pos - 2],
                    data[*pos - 1],
                ]) as usize,
                31 => {
                    loop {
                        if *pos >= data.len() {
                            return Err(CeremonyError::InvalidCbor);
                        }
                        if data[*pos] == 0xff {
                            *pos += 1;
                            break;
                        }
                        skip_cbor_value(data, pos)?;
                        skip_cbor_value(data, pos)?;
                    }
                    return Ok(());
                }
                _ => return Err(CeremonyError::InvalidCbor),
            };
            for _ in 0..count {
                skip_cbor_value(data, pos)?;
                skip_cbor_value(data, pos)?;
            }
        }
        6 => {
            skip_cbor_value(data, pos)?;
        }
        7 => match info {
            0..=23 => {}
            24..=27 => {}
            31 => {}
            _ => return Err(CeremonyError::InvalidCbor),
        },
        _ => return Err(CeremonyError::InvalidCbor),
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum AgentCeremonyError {
    ConsumeFailed(ReasonCode),
    AuditFailed,
    ResponseParseFailed(CeremonyError),
    InnerHandlerFailed,
    ScopeActivationFailed,
    CredentialMismatch,
    PromptDenied,
    PromptTimeout,
    PromptError,
    PendingResolveFailed,
    PromptBuildFailed,
    BoundAuthorizeFailed,
    NoPreparation,
    PreparationStale,
    CommandClassDenied,
    GetNextAssertionDenied,
    PolicyDenied(ReasonCode),
}

impl std::fmt::Display for AgentCeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConsumeFailed(r) => write!(f, "consume failed: {}", r),
            Self::AuditFailed => write!(f, "audit write failed"),
            Self::ResponseParseFailed(e) => write!(f, "response parse failed: {}", e),
            Self::InnerHandlerFailed => write!(f, "inner handler failed"),
            Self::ScopeActivationFailed => write!(f, "scope activation failed"),
            Self::CredentialMismatch => write!(f, "credential mismatch"),
            Self::PromptDenied => write!(f, "prompt denied by user"),
            Self::PromptTimeout => write!(f, "prompt timed out"),
            Self::PromptError => write!(f, "prompt error"),
            Self::PendingResolveFailed => write!(f, "pending request resolve failed"),
            Self::PromptBuildFailed => write!(f, "prompt request build failed"),
            Self::BoundAuthorizeFailed => write!(f, "bound authorization failed"),
            Self::NoPreparation => write!(f, "no active ceremony preparation"),
            Self::PreparationStale => write!(f, "ceremony preparation generation stale"),
            Self::CommandClassDenied => write!(f, "command class denied"),
            Self::GetNextAssertionDenied => write!(f, "get next assertion denied"),
            Self::PolicyDenied(r) => write!(f, "policy denied: {}", r),
        }
    }
}

impl std::error::Error for AgentCeremonyError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreparationError {
    AlreadyActive,
}

impl std::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyActive => write!(f, "preparation already active"),
        }
    }
}

impl std::error::Error for PreparationError {}

#[derive(Clone, Debug)]
pub struct BoundedUntrustedMetadata {
    rp_id: String,
    action: IntentAction,
    require_uv: bool,
    principal_reason: Option<String>,
}

impl BoundedUntrustedMetadata {
    pub fn new(rp_id: String, action: IntentAction, require_uv: bool) -> Self {
        Self {
            rp_id,
            action,
            require_uv,
            principal_reason: None,
        }
    }

    pub fn with_principal_reason(mut self, reason: Option<String>) -> Self {
        self.principal_reason = reason;
        self
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn action(&self) -> &IntentAction {
        &self.action
    }

    pub fn require_uv(&self) -> bool {
        self.require_uv
    }

    pub fn principal_reason(&self) -> Option<&str> {
        self.principal_reason.as_deref()
    }
}

#[derive(Clone, Debug)]
pub struct CeremonyPreparation {
    session_id: PrincipalSessionId,
    process_digest: ProcessIdentityDigest,
    policy_generation: PolicyGenerationId,
    policy_digest: PolicyDigest,
    credential_ref: Option<CredentialRef>,
    untrusted_metadata: BoundedUntrustedMetadata,
    generation: u64,
    clamped_grant_ttl_secs: u64,
    clamped_session_ttl_secs: u64,
    trusted_credential_label: Option<String>,
}

impl CeremonyPreparation {
    pub fn session_id(&self) -> &PrincipalSessionId {
        &self.session_id
    }

    pub fn process_digest(&self) -> &ProcessIdentityDigest {
        &self.process_digest
    }

    pub fn policy_generation(&self) -> &PolicyGenerationId {
        &self.policy_generation
    }

    pub fn policy_digest(&self) -> &PolicyDigest {
        &self.policy_digest
    }

    pub fn credential_ref(&self) -> Option<&CredentialRef> {
        self.credential_ref.as_ref()
    }

    pub fn untrusted_metadata(&self) -> &BoundedUntrustedMetadata {
        &self.untrusted_metadata
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn clamped_grant_ttl_secs(&self) -> u64 {
        self.clamped_grant_ttl_secs
    }

    pub fn clamped_session_ttl_secs(&self) -> u64 {
        self.clamped_session_ttl_secs
    }

    pub fn trusted_credential_label(&self) -> Option<&str> {
        self.trusted_credential_label.as_deref()
    }
}

pub struct CeremonyPreparationInput {
    pub session_id: PrincipalSessionId,
    pub process_digest: ProcessIdentityDigest,
    pub policy_generation: PolicyGenerationId,
    pub policy_digest: PolicyDigest,
    pub credential_ref: Option<CredentialRef>,
    pub untrusted_metadata: BoundedUntrustedMetadata,
    pub clamped_grant_ttl_secs: u64,
    pub clamped_session_ttl_secs: u64,
    pub trusted_credential_label: Option<String>,
}

struct SlotInner {
    preparation: Option<CeremonyPreparation>,
    generation_counter: u64,
}

pub struct CeremonyPreparationSlot {
    inner: Mutex<SlotInner>,
}

impl CeremonyPreparationSlot {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SlotInner {
                preparation: None,
                generation_counter: 0,
            }),
        }
    }

    pub fn install(
        self: &Arc<Self>,
        input: CeremonyPreparationInput,
    ) -> Result<CeremonyPreparationGuard, PreparationError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.preparation.is_some() {
            return Err(PreparationError::AlreadyActive);
        }
        inner.generation_counter += 1;
        let generation = inner.generation_counter;
        let preparation = CeremonyPreparation {
            session_id: input.session_id,
            process_digest: input.process_digest,
            policy_generation: input.policy_generation,
            policy_digest: input.policy_digest,
            credential_ref: input.credential_ref,
            untrusted_metadata: input.untrusted_metadata,
            generation,
            clamped_grant_ttl_secs: input.clamped_grant_ttl_secs,
            clamped_session_ttl_secs: input.clamped_session_ttl_secs,
            trusted_credential_label: input.trusted_credential_label,
        };
        inner.preparation = Some(preparation);
        Ok(CeremonyPreparationGuard {
            slot: Arc::clone(self),
            generation,
            armed: true,
        })
    }

    pub fn snapshot(&self) -> Option<CeremonyPreparation> {
        let inner = self.inner.lock().unwrap();
        inner.preparation.clone()
    }

    pub fn clear_matching(&self, generation: u64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(ref prep) = inner.preparation
            && prep.generation == generation
        {
            inner.preparation = None;
        }
    }

    pub fn clear_all(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.preparation = None;
    }

    #[cfg(test)]
    pub fn is_active(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.preparation.is_some()
    }
}

impl Default for CeremonyPreparationSlot {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CeremonyPreparationGuard {
    slot: Arc<CeremonyPreparationSlot>,
    generation: u64,
    armed: bool,
}

impl CeremonyPreparationGuard {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for CeremonyPreparationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.slot.clear_matching(self.generation);
        }
    }
}

pub struct StaticCeremonyContext {
    profile_id: ProfileId,
    endpoint_id: EndpointId,
    mode: PromptMode,
    policy_runtime: Arc<PolicyRuntime>,
    audit_gate: Arc<AuditGate>,
    prompt_handle: Arc<dyn PromptHandle>,
    interaction_manager: Option<Arc<AgentInteractionManager>>,
    ceremony_scope: CeremonyScope,
    preparation_slot: Arc<CeremonyPreparationSlot>,
    require_uv: bool,
    operation_lock: Arc<Mutex<()>>,
    #[cfg(test)]
    test_observer: Option<TestObserver>,
}

pub struct StaticCeremonyContextConfig {
    pub profile_id: ProfileId,
    pub endpoint_id: EndpointId,
    pub mode: PromptMode,
    pub policy_runtime: Arc<PolicyRuntime>,
    pub audit_gate: Arc<AuditGate>,
    pub ceremony_scope: CeremonyScope,
    pub require_uv: bool,
    pub prompt_handle: Arc<dyn PromptHandle>,
    pub preparation_slot: Arc<CeremonyPreparationSlot>,
}

impl StaticCeremonyContext {
    pub fn new(config: StaticCeremonyContextConfig) -> Self {
        Self {
            profile_id: config.profile_id,
            endpoint_id: config.endpoint_id,
            mode: config.mode,
            policy_runtime: config.policy_runtime,
            audit_gate: config.audit_gate,
            ceremony_scope: config.ceremony_scope,
            require_uv: config.require_uv,
            prompt_handle: config.prompt_handle,
            interaction_manager: None,
            preparation_slot: config.preparation_slot,
            operation_lock: Arc::new(Mutex::new(())),
            #[cfg(test)]
            test_observer: None,
        }
    }

    pub fn with_interaction_manager(mut self, manager: Arc<AgentInteractionManager>) -> Self {
        self.interaction_manager = Some(manager);
        self
    }

    pub fn with_operation_lock(mut self, lock: Arc<Mutex<()>>) -> Self {
        self.operation_lock = lock;
        self
    }

    #[cfg(test)]
    pub fn with_test_observer(mut self, observer: TestObserver) -> Self {
        self.test_observer = Some(observer);
        self
    }

    #[cfg(test)]
    fn emit_observation(
        &self,
        command_class: CommandClass,
        terminal_result: TerminalResult,
        up: bool,
        uv: bool,
        correlation_id: u64,
    ) {
        if let Some(ref observer) = self.test_observer {
            observer.record(CeremonyObservation {
                command_class,
                terminal_result,
                up,
                uv,
                correlation_id,
            });
        }
    }

    #[cfg(test)]
    fn mint_correlation_id(&self) -> u64 {
        self.test_observer
            .as_ref()
            .map(|o| o.mint_correlation_id())
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub fn require_uv(&self) -> bool {
        self.require_uv
    }

    #[cfg(test)]
    pub fn preparation_slot(&self) -> &Arc<CeremonyPreparationSlot> {
        &self.preparation_slot
    }

    #[cfg(test)]
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    #[cfg(test)]
    pub fn endpoint_id(&self) -> &EndpointId {
        &self.endpoint_id
    }
}

pub struct AgentCeremonyHandler<H: CommandHandler> {
    inner: H,
    ctx: StaticCeremonyContext,
}

impl<H: CommandHandler> AgentCeremonyHandler<H> {
    pub fn new(inner: H, ctx: StaticCeremonyContext) -> Self {
        Self { inner, ctx }
    }

    fn clear_preparation(&self, generation: u64) {
        self.ctx.preparation_slot.clear_matching(generation);
    }

    fn handle_ceremony_command(
        &mut self,
        raw: &[u8],
        cmd_byte: u8,
    ) -> Result<Vec<u8>, AgentCeremonyError> {
        let preparation = self
            .ctx
            .preparation_slot
            .snapshot()
            .ok_or(AgentCeremonyError::NoPreparation)?;

        let generation = preparation.generation();

        let metadata = preparation.untrusted_metadata();
        let rp_id = metadata.rp_id().to_string();
        let require_uv = metadata.require_uv();
        let intent_action = metadata.action().clone();

        let action = match &intent_action {
            IntentAction::Register => AuditAction::Register,
            IntentAction::Authenticate => AuditAction::Authenticate,
        };

        let parsed = parse_ceremony_request(raw).map_err(|e| {
            self.clear_preparation(generation);
            AgentCeremonyError::ResponseParseFailed(e)
        })?;

        match (&intent_action, &parsed) {
            (IntentAction::Register, ParsedCeremonyRequest::MakeCredential(_)) => {}
            (IntentAction::Authenticate, ParsedCeremonyRequest::GetAssertion(_)) => {}
            (IntentAction::Register, ParsedCeremonyRequest::GetAssertion(_)) => {
                self.ctx.preparation_slot.clear_all();
                return Err(AgentCeremonyError::CredentialMismatch);
            }
            (IntentAction::Authenticate, ParsedCeremonyRequest::MakeCredential(_)) => {
                self.ctx.preparation_slot.clear_all();
                return Err(AgentCeremonyError::CredentialMismatch);
            }
        }

        let parsed_rp_id = match &parsed {
            ParsedCeremonyRequest::MakeCredential(mc) => &mc.rp_id,
            ParsedCeremonyRequest::GetAssertion(ga) => &ga.rp_id,
        };
        let prep_rp_normalized = metadata.rp_id().trim().to_ascii_lowercase();
        let parsed_rp_normalized = parsed_rp_id.trim().to_ascii_lowercase();
        if prep_rp_normalized != parsed_rp_normalized {
            self.ctx.preparation_slot.clear_all();
            return Err(AgentCeremonyError::CredentialMismatch);
        }

        let request_cred_ref = match &parsed {
            ParsedCeremonyRequest::MakeCredential(_) => None::<CredentialRef>,
            ParsedCeremonyRequest::GetAssertion(ga) => {
                if ga.allow_refs.len() == 1 {
                    Some(ga.allow_refs[0].clone())
                } else {
                    None
                }
            }
        };

        let ceremony_policy = self
            .ctx
            .policy_runtime
            .ceremony_policy(
                &self.ctx.profile_id,
                preparation.policy_generation(),
                preparation.policy_digest(),
                &rp_id,
                &intent_action,
            )
            .ok_or_else(|| {
                self.clear_preparation(generation);
                AgentCeremonyError::PolicyDenied(ReasonCode::GenerationStale)
            })?;

        let effective_uv = require_uv
            || ceremony_policy.user_verification != UserVerificationSource::None
            || self.ctx.require_uv;

        if let Some(expected) = preparation.credential_ref() {
            match &parsed {
                ParsedCeremonyRequest::MakeCredential(_) => {}
                ParsedCeremonyRequest::GetAssertion(ga) => {
                    if ga.allow_refs.len() != 1 {
                        self.ctx.preparation_slot.clear_all();
                        return Err(AgentCeremonyError::CredentialMismatch);
                    }
                    if ga.allow_refs[0] != *expected {
                        self.ctx.preparation_slot.clear_all();
                        return Err(AgentCeremonyError::CredentialMismatch);
                    }
                }
            }
        }

        let effective_cred_ref = request_cred_ref
            .clone()
            .or_else(|| preparation.credential_ref().cloned());

        let tuple = CeremonyTuple {
            profile_id: self.ctx.profile_id.clone(),
            session_id: preparation.session_id().clone(),
            endpoint_id: self.ctx.endpoint_id.clone(),
            process_digest: preparation.process_digest().clone(),
            policy_generation: preparation.policy_generation().clone(),
            policy_digest: preparation.policy_digest().clone(),
            action: intent_action.clone(),
            rp_id: rp_id.clone(),
            credential_ref: effective_cred_ref.clone(),
        };

        match ceremony_policy.authorization {
            AgentAuthorization::Deny => {
                self.audit_policy_deny(&rp_id, action, PolicyDenyReason::ActionNotAllowed)?;
                let _ = self.ctx.policy_runtime.ceremony_deny_pending(&tuple);
                self.clear_preparation(generation);
                return Err(AgentCeremonyError::PolicyDenied(
                    ReasonCode::ActionNotAllowed,
                ));
            }
            AgentAuthorization::Confirm => {
                let prompt_action = match action {
                    AuditAction::Register => PromptAction::Register,
                    AuditAction::Authenticate => PromptAction::Authenticate,
                };
                let mut prompt_builder = PromptRequest::builder()
                    .profile_id(self.ctx.profile_id.clone())
                    .mode(self.ctx.mode)
                    .action(prompt_action)
                    .rp_id(&rp_id)
                    .credential_ref_opt(preparation.credential_ref().cloned())
                    .grant_ttl_secs(preparation.clamped_grant_ttl_secs())
                    .session_ttl_secs(preparation.clamped_session_ttl_secs());

                if let Some(label) = preparation.trusted_credential_label() {
                    prompt_builder = prompt_builder.credential_label(label);
                }
                if let Some(reason) = preparation.untrusted_metadata().principal_reason() {
                    prompt_builder = prompt_builder.untrusted_reason(reason);
                }

                let prompt_request = prompt_builder.build().map_err(|_| {
                    self.clear_preparation(generation);
                    AgentCeremonyError::PromptBuildFailed
                })?;
                self.audit_prompt_display(&prompt_request, effective_cred_ref.as_ref())?;
                let prompt_result = self.ctx.prompt_handle.prompt(&prompt_request);

                match prompt_result.decision {
                    super::prompt::PromptDecision::Approved => {
                        self.audit_prompt_approve(&prompt_request, prompt_result.latency_ms)?;
                    }
                    super::prompt::PromptDecision::Denied => {
                        self.audit_prompt_deny(&prompt_request, prompt_result.latency_ms)?;
                        let _ = self.ctx.policy_runtime.ceremony_deny_pending(&tuple);
                        self.clear_preparation(generation);
                        return Err(AgentCeremonyError::PromptDenied);
                    }
                    super::prompt::PromptDecision::Timeout => {
                        self.audit_prompt_timeout(&prompt_request)?;
                        let _ = self.ctx.policy_runtime.ceremony_deny_pending(&tuple);
                        self.clear_preparation(generation);
                        return Err(AgentCeremonyError::PromptTimeout);
                    }
                    super::prompt::PromptDecision::Error => {
                        let error_kind = prompt_result
                            .error_kind
                            .unwrap_or(super::prompt::PromptErrorKind::InternalError);
                        self.audit_prompt_error(&prompt_request, error_kind)?;
                        let _ = self.ctx.policy_runtime.ceremony_deny_pending(&tuple);
                        self.clear_preparation(generation);
                        return Err(AgentCeremonyError::PromptError);
                    }
                }
            }
            AgentAuthorization::Allow => {}
        }

        let approval = TrustedApproval::new();
        let bound = self
            .ctx
            .policy_runtime
            .ceremony_resolve_pending(&tuple, &approval)
            .map_err(|_| {
                self.clear_preparation(generation);
                AgentCeremonyError::PendingResolveFailed
            })?;

        let auth_request = AuthorizationRequest {
            profile_id: self.ctx.profile_id.clone(),
            session_id: preparation.session_id().clone(),
            endpoint_id: self.ctx.endpoint_id.clone(),
            process_digest: preparation.process_digest().clone(),
            policy_generation_id: preparation.policy_generation().clone(),
            policy_digest: preparation.policy_digest().clone(),
            action: intent_action.clone(),
            rp_id: rp_id.clone(),
            credential_ref: effective_cred_ref.clone(),
            uv_enforced: effective_uv,
        };

        let (decision, handle) = self
            .ctx
            .policy_runtime
            .authorize_bound(&bound, &auth_request);

        if !decision.is_allowed() {
            let deny_reason = reason_code_to_policy_deny_reason(decision.reason);
            let _ = self.audit_policy_deny(&rp_id, action, deny_reason);
            self.clear_preparation(generation);
            return Err(AgentCeremonyError::BoundAuthorizeFailed);
        }

        let handle = handle.ok_or_else(|| {
            self.clear_preparation(generation);
            AgentCeremonyError::BoundAuthorizeFailed
        })?;

        self.audit_policy_allow(&rp_id, action, &ceremony_policy)?;

        let ceremony_id = handle.ceremony_id().clone();
        let grant_id = handle.grant_id().cloned();
        let intent_id = handle.intent_id().ok_or_else(|| {
            self.clear_preparation(generation);
            AgentCeremonyError::AuditFailed
        })?;
        let profile_id = handle.profile_id().clone();

        self.audit_ceremony_start(&ceremony_id, grant_id, intent_id, &profile_id, action)?;

        let consume_result = self.ctx.policy_runtime.consume_authorization(&handle);
        if let Err(reason) = consume_result {
            let _ = self.audit_ceremony_failure(
                &ceremony_id,
                super::audit_events::CeremonyFailReason::ConsumeFailed,
            );
            self.clear_preparation(generation);
            return Err(AgentCeremonyError::ConsumeFailed(reason));
        }

        let scope_guard = match &intent_action {
            IntentAction::Register => self
                .ctx
                .ceremony_scope
                .activate_register_for_rp(&rp_id)
                .map_err(|_| {
                    self.clear_preparation(generation);
                    AgentCeremonyError::ScopeActivationFailed
                })?,
            IntentAction::Authenticate => {
                let cred_ref = effective_cred_ref.ok_or_else(|| {
                    self.clear_preparation(generation);
                    AgentCeremonyError::CredentialMismatch
                })?;
                self.ctx
                    .ceremony_scope
                    .activate_authenticate_for_rp(cred_ref, &rp_id)
                    .map_err(|_| {
                        self.clear_preparation(generation);
                        AgentCeremonyError::ScopeActivationFailed
                    })?
            }
        };

        let interaction_guard = if let Some(ref manager) = self.ctx.interaction_manager {
            let interaction_gen = self
                .ctx
                .ceremony_scope
                .active_cred_ref()
                .map(|_| 0)
                .unwrap_or(0);
            manager.mint(
                rp_id.clone(),
                intent_action.clone(),
                interaction_gen,
                ceremony_policy.user_presence != UserPresenceSource::None,
                ceremony_policy.user_verification == UserVerificationSource::Agent,
                Duration::from_secs(60),
            );
            Some(InteractionTokenGuard::new(manager.clone()))
        } else {
            None
        };

        let response = self.inner.handle_command(Cmd::Cbor, raw).map_err(|_| {
            self.clear_preparation(generation);
            AgentCeremonyError::InnerHandlerFailed
        })?;

        drop(interaction_guard);
        drop(scope_guard);

        if response.is_empty() {
            let _ = self.audit_ceremony_failure(
                &ceremony_id,
                super::audit_events::CeremonyFailReason::InnerHandlerError,
            );
            self.clear_preparation(generation);
            return Err(AgentCeremonyError::InnerHandlerFailed);
        }

        if response[0] != CTAP_OK {
            let _ = self.audit_ceremony_failure(
                &ceremony_id,
                super::audit_events::CeremonyFailReason::InnerHandlerError,
            );
            self.clear_preparation(generation);
            return Err(AgentCeremonyError::InnerHandlerFailed);
        }

        let parsed_response = parse_ceremony_response(cmd_byte, &response, effective_uv);
        match parsed_response {
            Ok(_) => {
                self.audit_ceremony_success(&ceremony_id)?;
                self.clear_preparation(generation);
                Ok(response)
            }
            Err(e) => {
                let fail_reason = match e {
                    CeremonyError::UvNotSet => super::audit_events::CeremonyFailReason::UvRequired,
                    CeremonyError::UpNotSet => super::audit_events::CeremonyFailReason::UvRequired,
                    _ => super::audit_events::CeremonyFailReason::ResponseParseError,
                };
                let _ = self.audit_ceremony_failure(&ceremony_id, fail_reason);
                self.clear_preparation(generation);
                Err(AgentCeremonyError::ResponseParseFailed(e))
            }
        }
    }

    fn audit_policy_allow(
        &self,
        rp_id: &str,
        action: AuditAction,
        policy: &passless_core::agent::AgentCeremonyPolicy,
    ) -> Result<(), AgentCeremonyError> {
        let event = PolicyAllowBuilder::new(self.ctx.profile_id.clone(), action, rp_id)
            .evidence_sources(
                &policy.authorization.to_string(),
                &policy.user_presence.to_string(),
                &policy.user_verification.to_string(),
            )
            .build();
        self.ctx
            .audit_gate
            .record(event)
            .map_err(|_| AgentCeremonyError::AuditFailed)?;
        Ok(())
    }

    fn audit_policy_deny(
        &self,
        rp_id: &str,
        action: AuditAction,
        reason: PolicyDenyReason,
    ) -> Result<(), AgentCeremonyError> {
        let event =
            PolicyDenyBuilder::new(self.ctx.profile_id.clone(), action, rp_id, reason).build();
        self.ctx
            .audit_gate
            .record(event)
            .map_err(|_| AgentCeremonyError::AuditFailed)?;
        Ok(())
    }

    fn audit_prompt_display(
        &self,
        request: &PromptRequest,
        credential_ref: Option<&CredentialRef>,
    ) -> Result<(), AgentCeremonyError> {
        let event = PromptDisplayBuilder::new(
            request.profile_id().clone(),
            request.mode(),
            request.action(),
            request.rp_id(),
            credential_ref.cloned(),
            request.grant_ttl_secs(),
            request.session_ttl_secs(),
        )
        .build();
        self.ctx
            .audit_gate
            .record(event)
            .map_err(|_| AgentCeremonyError::AuditFailed)?;
        Ok(())
    }

    fn audit_prompt_approve(
        &self,
        request: &PromptRequest,
        latency_ms: u64,
    ) -> Result<(), AgentCeremonyError> {
        let event = PromptApproveBuilder::new(
            request.profile_id().clone(),
            request.mode(),
            request.action(),
            request.rp_id(),
            latency_ms,
        )
        .build();
        self.ctx
            .audit_gate
            .record(event)
            .map_err(|_| AgentCeremonyError::AuditFailed)?;
        Ok(())
    }

    fn audit_prompt_deny(
        &self,
        request: &PromptRequest,
        latency_ms: u64,
    ) -> Result<(), AgentCeremonyError> {
        let event = PromptDenyBuilder::new(
            request.profile_id().clone(),
            request.mode(),
            request.action(),
            request.rp_id(),
            latency_ms,
        )
        .build();
        self.ctx
            .audit_gate
            .record(event)
            .map_err(|_| AgentCeremonyError::AuditFailed)?;
        Ok(())
    }

    fn audit_prompt_timeout(&self, request: &PromptRequest) -> Result<(), AgentCeremonyError> {
        let event = PromptTimeoutBuilder::new(
            request.profile_id().clone(),
            request.mode(),
            request.action(),
            request.rp_id(),
            60,
        )
        .build();
        self.ctx
            .audit_gate
            .record(event)
            .map_err(|_| AgentCeremonyError::AuditFailed)?;
        Ok(())
    }

    fn audit_prompt_error(
        &self,
        request: &PromptRequest,
        error_kind: super::prompt::PromptErrorKind,
    ) -> Result<(), AgentCeremonyError> {
        let event = PromptErrorBuilder::new(
            request.profile_id().clone(),
            request.mode(),
            request.action(),
            request.rp_id(),
            error_kind,
        )
        .build();
        self.ctx
            .audit_gate
            .record(event)
            .map_err(|_| AgentCeremonyError::AuditFailed)?;
        Ok(())
    }

    fn audit_ceremony_start(
        &self,
        ceremony_id: &CeremonyId,
        grant_id: Option<passless_core::agent::GrantId>,
        intent_id: &passless_core::agent::IntentId,
        profile_id: &ProfileId,
        action: AuditAction,
    ) -> Result<(), AgentCeremonyError> {
        let event = CeremonyStartBuilder::new(
            ceremony_id,
            grant_id,
            intent_id.clone(),
            profile_id.clone(),
            action,
        )
        .build();
        self.ctx
            .audit_gate
            .record(event)
            .map_err(|_| AgentCeremonyError::AuditFailed)?;
        Ok(())
    }

    fn audit_ceremony_success(&self, ceremony_id: &CeremonyId) -> Result<(), AgentCeremonyError> {
        let event = CeremonySuccessBuilder::new(ceremony_id).build();
        self.ctx
            .audit_gate
            .record(event)
            .map_err(|_| AgentCeremonyError::AuditFailed)?;
        Ok(())
    }

    fn audit_ceremony_failure(
        &self,
        ceremony_id: &CeremonyId,
        reason: super::audit_events::CeremonyFailReason,
    ) -> Result<(), AgentCeremonyError> {
        let event = CeremonyFailureBuilder::new(ceremony_id, reason).build();
        self.ctx
            .audit_gate
            .record(event)
            .map_err(|_| AgentCeremonyError::AuditFailed)?;
        Ok(())
    }
}

impl<H: CommandHandler> CommandHandler for AgentCeremonyHandler<H> {
    fn handle_command(&mut self, cmd: Cmd, data: &[u8]) -> soft_fido2_transport::Result<Vec<u8>> {
        if cmd != Cmd::Cbor {
            return Err(soft_fido2_transport::Error::InvalidCommand);
        }

        if data.is_empty() {
            return Ok(operation_denied_response());
        }

        let cmd_byte = data[0];
        let cmd_class = classify_command(cmd_byte);

        #[cfg(test)]
        let correlation_id = self.ctx.mint_correlation_id();

        match cmd_class {
            CommandClass::Denied => {
                #[cfg(test)]
                self.ctx.emit_observation(
                    cmd_class,
                    TerminalResult::CommandClassDenied,
                    false,
                    false,
                    correlation_id,
                );
                return Ok(operation_denied_response());
            }
            CommandClass::SafeNonCeremony => {
                let result = self.inner.handle_command(Cmd::Cbor, data).map_err(|_| {
                    #[cfg(test)]
                    self.ctx.emit_observation(
                        cmd_class,
                        TerminalResult::InnerHandlerError,
                        false,
                        false,
                        correlation_id,
                    );
                    soft_fido2_transport::Error::Other("inner handler failed".into())
                });
                #[cfg(test)]
                if result.is_ok() {
                    self.ctx.emit_observation(
                        cmd_class,
                        TerminalResult::Success,
                        false,
                        false,
                        correlation_id,
                    );
                }
                return result;
            }
            CommandClass::Unknown => {
                #[cfg(test)]
                self.ctx.emit_observation(
                    cmd_class,
                    TerminalResult::CommandClassDenied,
                    false,
                    false,
                    correlation_id,
                );
                return Ok(operation_denied_response());
            }
            CommandClass::Ceremony => {}
        }

        let op_lock = self.ctx.operation_lock.clone();
        let _op = op_lock
            .lock()
            .map_err(|_| soft_fido2_transport::Error::Other("operation lock poisoned".into()))?;

        match self.handle_ceremony_command(data, cmd_byte) {
            Ok(response) => {
                #[cfg(test)]
                {
                    let (up, uv) = extract_up_uv_from_response(cmd_byte, &response);
                    self.ctx.emit_observation(
                        cmd_class,
                        TerminalResult::Success,
                        up,
                        uv,
                        correlation_id,
                    );
                }
                Ok(response)
            }
            Err(e) => {
                #[cfg(test)]
                {
                    let terminal = map_ceremony_error_to_terminal(&e);
                    self.ctx
                        .emit_observation(cmd_class, terminal, false, false, correlation_id);
                }
                let _ = e;
                Ok(operation_denied_response())
            }
        }
    }
}

fn operation_denied_response() -> Vec<u8> {
    vec![CTAP_ERR_OPERATION_DENIED]
}

#[cfg(test)]
pub(crate) fn extract_up_uv_from_response(cmd_byte: u8, response: &[u8]) -> (bool, bool) {
    if response.is_empty() || response[0] != CTAP_OK {
        return (false, false);
    }
    let cbor_bytes = &response[1..];
    let value: cbor::Value = match cbor::from_slice(cbor_bytes) {
        Ok(v) => v,
        Err(_) => return (false, false),
    };
    let map = match &value {
        cbor::Value::Map(m) => m,
        _ => return (false, false),
    };
    let auth_data = match map
        .iter()
        .find(|(k, _)| **k == cbor::Value::Integer(RESP_KEY_AUTH_DATA as i128))
    {
        Some((_, cbor::Value::Bytes(b))) if b.len() >= AUTH_DATA_MIN_LEN => b,
        _ => return (false, false),
    };
    let flags = auth_data[AUTH_DATA_FLAGS_OFFSET];
    let up = flags & FLAG_UP != 0;
    let uv = flags & FLAG_UV != 0;
    let _ = cmd_byte;
    (up, uv)
}

#[cfg(test)]
pub(crate) fn map_ceremony_error_to_terminal(e: &AgentCeremonyError) -> TerminalResult {
    match e {
        AgentCeremonyError::ConsumeFailed(_) => TerminalResult::ConsumeFailed,
        AgentCeremonyError::AuditFailed => TerminalResult::AuditFailed,
        AgentCeremonyError::ResponseParseFailed(CeremonyError::NonZeroStatus) => {
            TerminalResult::NonZeroStatus
        }
        AgentCeremonyError::ResponseParseFailed(_) => TerminalResult::ResponseParseError,
        AgentCeremonyError::InnerHandlerFailed => TerminalResult::InnerHandlerError,
        AgentCeremonyError::ScopeActivationFailed => TerminalResult::ScopeActivationFailed,
        AgentCeremonyError::CredentialMismatch => TerminalResult::CredentialMismatch,
        AgentCeremonyError::PromptDenied => TerminalResult::PromptDenied,
        AgentCeremonyError::PromptTimeout => TerminalResult::PromptTimeout,
        AgentCeremonyError::PromptError => TerminalResult::PromptError,
        AgentCeremonyError::PendingResolveFailed => TerminalResult::ResponseParseError,
        AgentCeremonyError::PromptBuildFailed => TerminalResult::PromptError,
        AgentCeremonyError::BoundAuthorizeFailed => TerminalResult::BoundAuthorizeFailed,
        AgentCeremonyError::NoPreparation => TerminalResult::NoPreparation,
        AgentCeremonyError::PreparationStale => TerminalResult::PreparationStale,
        AgentCeremonyError::CommandClassDenied => TerminalResult::CommandClassDenied,
        AgentCeremonyError::GetNextAssertionDenied => TerminalResult::GetNextAssertionDenied,
        AgentCeremonyError::PolicyDenied(_) => TerminalResult::DeniedByPolicy,
    }
}

fn reason_code_to_policy_deny_reason(reason: ReasonCode) -> PolicyDenyReason {
    match reason {
        ReasonCode::DefaultDeny => PolicyDenyReason::DefaultDeny,
        ReasonCode::ActionNotAllowed => PolicyDenyReason::ActionNotAllowed,
        ReasonCode::RpIdNotExactMatch | ReasonCode::SuffixNotExact => {
            PolicyDenyReason::RpIdNotMatch
        }
        ReasonCode::CredentialNotExactMatch | ReasonCode::EmptyCredentialList => {
            PolicyDenyReason::CredentialNotMatch
        }
        ReasonCode::GrantExpired => PolicyDenyReason::GrantExpired,
        ReasonCode::GrantNotFound | ReasonCode::GrantMissingForDelegated => {
            PolicyDenyReason::GrantNotFound
        }
        ReasonCode::SessionMismatch
        | ReasonCode::EndpointMismatch
        | ReasonCode::ProcessMismatch => PolicyDenyReason::SessionMismatch,
        ReasonCode::UvRequired => PolicyDenyReason::UvRequired,
        ReasonCode::StaleGeneration | ReasonCode::GenerationStale => {
            PolicyDenyReason::StaleGeneration
        }
        _ => PolicyDenyReason::DefaultDeny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cbor::Value;

    fn cbor_map(pairs: Vec<(Value, Value)>) -> Vec<u8> {
        let map: std::collections::BTreeMap<Value, Value> = pairs.into_iter().collect();
        cbor::to_vec(&Value::Map(map)).unwrap()
    }

    fn cbor_text(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    fn cbor_bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }

    fn cbor_int(i: u64) -> Value {
        Value::Integer(i as i128)
    }

    fn cbor_bool(b: bool) -> Value {
        Value::Bool(b)
    }

    fn make_rp_entity(rp_id: &str) -> Value {
        let mut rp_map = std::collections::BTreeMap::new();
        rp_map.insert(cbor_text("id"), cbor_text(rp_id));
        Value::Map(rp_map.into_iter().collect())
    }

    fn make_descriptor(cred_id: &[u8]) -> Value {
        let mut desc_map = std::collections::BTreeMap::new();
        desc_map.insert(cbor_text("id"), cbor_bytes(cred_id));
        desc_map.insert(cbor_text("type"), cbor_text("public-key"));
        Value::Map(desc_map.into_iter().collect())
    }

    fn make_credential_bytes(rp_id: &str) -> Vec<u8> {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity(rp_id));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap()
    }

    fn make_assertion_bytes(rp_id: &str) -> Vec<u8> {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text(rp_id));
        map.insert(cbor_int(0x02), cbor_bytes(&[0xbb; 32]));
        cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap()
    }

    fn make_auth_data(flags: u8) -> Vec<u8> {
        let mut data = vec![0u8; 37];
        data[32] = flags;
        data
    }

    fn make_mc_response(auth_data: &[u8]) -> Vec<u8> {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("none"));
        map.insert(cbor_int(0x02), cbor_bytes(auth_data));
        map.insert(cbor_int(0x03), Value::Map(vec![].into_iter().collect()));
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());
        raw
    }

    fn make_ga_response(auth_data: &[u8]) -> Vec<u8> {
        let mut cred_desc = std::collections::BTreeMap::new();
        cred_desc.insert(cbor_text("id"), cbor_bytes(&[0xcc; 32]));
        cred_desc.insert(cbor_text("type"), cbor_text("public-key"));

        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), Value::Map(cred_desc.into_iter().collect()));
        map.insert(cbor_int(0x02), cbor_bytes(auth_data));
        map.insert(cbor_int(0x03), cbor_bytes(&[0xdd; 64]));
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());
        raw
    }

    #[test]
    fn test_parse_command_make_credential() {
        assert_eq!(parse_command(&[0x01]).unwrap(), Command::MakeCredential);
    }

    #[test]
    fn test_parse_command_get_assertion() {
        assert_eq!(parse_command(&[0x02]).unwrap(), Command::GetAssertion);
    }

    #[test]
    fn test_parse_command_get_info() {
        assert_eq!(parse_command(&[0x04]).unwrap(), Command::GetInfo);
    }

    #[test]
    fn test_parse_command_client_pin() {
        assert_eq!(parse_command(&[0x06]).unwrap(), Command::ClientPin);
    }

    #[test]
    fn test_parse_command_reset() {
        assert_eq!(parse_command(&[0x07]).unwrap(), Command::Reset);
    }

    #[test]
    fn test_parse_command_credential_mgmt() {
        assert_eq!(parse_command(&[0x0a]).unwrap(), Command::CredentialMgmt);
    }

    #[test]
    fn test_parse_command_selection() {
        assert_eq!(parse_command(&[0x0b]).unwrap(), Command::Selection);
    }

    #[test]
    fn test_parse_command_vendor() {
        assert_eq!(parse_command(&[0x40]).unwrap(), Command::Vendor(0x40));
        assert_eq!(parse_command(&[0xbf]).unwrap(), Command::Vendor(0xbf));
    }

    #[test]
    fn test_parse_command_unknown() {
        assert_eq!(parse_command(&[0x3f]).unwrap(), Command::Unknown(0x3f));
        assert_eq!(parse_command(&[0xc0]).unwrap(), Command::Unknown(0xc0));
        assert_eq!(parse_command(&[0xff]).unwrap(), Command::Unknown(0xff));
    }

    #[test]
    fn test_parse_command_empty() {
        assert_eq!(parse_command(&[]), Err(CeremonyError::EmptyInput));
    }

    #[test]
    fn test_classify_ceremony_commands() {
        assert_eq!(classify_command(0x01), CommandClass::Ceremony);
        assert_eq!(classify_command(0x02), CommandClass::Ceremony);
    }

    #[test]
    fn test_classify_safe_non_ceremony() {
        assert_eq!(classify_command(0x04), CommandClass::SafeNonCeremony);
        assert_eq!(classify_command(0x06), CommandClass::SafeNonCeremony);
        assert_eq!(classify_command(0x0b), CommandClass::SafeNonCeremony);
    }

    #[test]
    fn test_classify_denied() {
        assert_eq!(classify_command(0x07), CommandClass::Denied);
        assert_eq!(classify_command(0x0a), CommandClass::Denied);
        assert_eq!(classify_command(0x40), CommandClass::Denied);
        assert_eq!(classify_command(0x41), CommandClass::Denied);
        assert_eq!(classify_command(0xbf), CommandClass::Denied);
    }

    #[test]
    fn test_classify_unknown() {
        assert_eq!(classify_command(0x03), CommandClass::Unknown);
        assert_eq!(classify_command(0x05), CommandClass::Unknown);
        assert_eq!(classify_command(0xff), CommandClass::Unknown);
    }

    #[test]
    fn test_parse_make_credential_basic() {
        let cbor_data = make_credential_bytes("example.com");
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::MakeCredential(mc) => {
                assert_eq!(mc.rp_id, "example.com");
                assert!(!mc.require_uv);
                assert!(mc.exclude_refs.is_empty());
            }
            _ => panic!("expected MakeCredential"),
        }
    }

    #[test]
    fn test_parse_make_credential_rp_normalization() {
        let cbor_data = make_credential_bytes("EXAMPLE.COM");
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::MakeCredential(mc) => {
                assert_eq!(mc.rp_id, "example.com");
            }
            _ => panic!("expected MakeCredential"),
        }
    }

    #[test]
    fn test_parse_make_credential_with_exclude_list() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(
            cbor_int(0x05),
            Value::Array(vec![
                make_descriptor(b"cred-id-1"),
                make_descriptor(b"cred-id-2"),
            ]),
        );

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::MakeCredential(mc) => {
                assert_eq!(mc.rp_id, "example.com");
                assert_eq!(mc.exclude_refs.len(), 2);
            }
            _ => panic!("expected MakeCredential"),
        }
    }

    #[test]
    fn test_parse_make_credential_with_uv_option() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        let mut opts = std::collections::BTreeMap::new();
        opts.insert(cbor_text("uv"), cbor_bool(true));
        opts.insert(cbor_text("rk"), cbor_bool(true));
        map.insert(cbor_int(0x07), Value::Map(opts.into_iter().collect()));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::MakeCredential(mc) => {
                assert!(mc.require_uv);
            }
            _ => panic!("expected MakeCredential"),
        }
    }

    #[test]
    fn test_parse_make_credential_missing_rp() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::MissingField("rp"))));
    }

    #[test]
    fn test_parse_make_credential_missing_client_data_hash() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::MissingField("clientDataHash"))
        ));
    }

    #[test]
    fn test_parse_make_credential_missing_pub_key_cred_params() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::MissingField("pubKeyCredParams"))
        ));
    }

    #[test]
    fn test_parse_make_credential_exclude_list_too_large() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );

        let descriptors: Vec<Value> = (0..MAX_DESCRIPTOR_COUNT + 1)
            .map(|i| make_descriptor(&[i as u8; 32]))
            .collect();
        map.insert(cbor_int(0x05), Value::Array(descriptors));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::TooManyDescriptors)));
    }

    #[test]
    fn test_parse_make_credential_credential_id_too_large() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(
            cbor_int(0x05),
            Value::Array(vec![make_descriptor(&[0xaa; MAX_CREDENTIAL_ID_SIZE + 1])]),
        );

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::CredentialIdTooLarge)));
    }

    #[test]
    fn test_parse_make_credential_invalid_rp_id_scheme() {
        let cbor_data = make_credential_bytes("https://example.com");
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::RpIdInvalid)));
    }

    #[test]
    fn test_parse_make_credential_invalid_rp_id_single_label() {
        let cbor_data = make_credential_bytes("localhost");
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::RpIdInvalid)));
    }

    #[test]
    fn test_parse_make_credential_invalid_rp_id_empty() {
        let cbor_data = make_credential_bytes("");
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::RpIdEmpty)));
    }

    #[test]
    fn test_parse_make_credential_invalid_rp_id_trailing_dot() {
        let cbor_data = make_credential_bytes("example.com.");
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::RpIdInvalid)));
    }

    #[test]
    fn test_parse_make_credential_invalid_rp_id_port() {
        let cbor_data = make_credential_bytes("example.com:443");
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::RpIdInvalid)));
    }

    #[test]
    fn test_parse_make_credential_invalid_rp_id_wildcard() {
        let cbor_data = make_credential_bytes("*.example.com");
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::RpIdInvalid)));
    }

    #[test]
    fn test_parse_make_credential_wrong_type_rp_id() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), cbor_bool(true));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::InvalidFieldType("rp"))));
    }

    #[test]
    fn test_parse_make_credential_invalid_cbor() {
        let mut raw = vec![0x01];
        raw.extend_from_slice(&[0xff, 0xff, 0xff]);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::InvalidCbor)));
    }

    #[test]
    fn test_parse_make_credential_not_a_map() {
        let cbor_data = cbor::to_vec(&Value::Array(vec![cbor_int(1)])).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::NotAMap)));
    }

    #[test]
    fn test_parse_make_credential_duplicate_keys() {
        let raw_cbor = [
            0xa2, 0x01, 0x6b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
            0x01, 0x69, b'o', b't', b'h', b'e', b'r', b'.', b'c', b'o', b'm',
        ];
        assert!(has_duplicate_keys(&raw_cbor).unwrap());

        let mut raw = vec![0x01];
        raw.extend_from_slice(&raw_cbor);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::DuplicateKey)));
    }

    #[test]
    fn test_parse_get_assertion_basic() {
        let cbor_data = make_assertion_bytes("example.com");
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::GetAssertion(ga) => {
                assert_eq!(ga.rp_id, "example.com");
                assert!(!ga.require_uv);
                assert!(ga.allow_refs.is_empty());
            }
            _ => panic!("expected GetAssertion"),
        }
    }

    #[test]
    fn test_parse_get_assertion_rp_normalization() {
        let cbor_data = make_assertion_bytes("EXAMPLE.COM");
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::GetAssertion(ga) => {
                assert_eq!(ga.rp_id, "example.com");
            }
            _ => panic!("expected GetAssertion"),
        }
    }

    #[test]
    fn test_parse_get_assertion_with_allow_list() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("example.com"));
        map.insert(cbor_int(0x02), cbor_bytes(&[0xbb; 32]));
        map.insert(
            cbor_int(0x03),
            Value::Array(vec![
                make_descriptor(b"cred-1"),
                make_descriptor(b"cred-2"),
                make_descriptor(b"cred-3"),
            ]),
        );

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::GetAssertion(ga) => {
                assert_eq!(ga.rp_id, "example.com");
                assert_eq!(ga.allow_refs.len(), 3);
            }
            _ => panic!("expected GetAssertion"),
        }
    }

    #[test]
    fn test_parse_get_assertion_with_uv_option() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("example.com"));
        map.insert(cbor_int(0x02), cbor_bytes(&[0xbb; 32]));
        let mut opts = std::collections::BTreeMap::new();
        opts.insert(cbor_text("uv"), cbor_bool(true));
        map.insert(cbor_int(0x05), Value::Map(opts.into_iter().collect()));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::GetAssertion(ga) => {
                assert!(ga.require_uv);
            }
            _ => panic!("expected GetAssertion"),
        }
    }

    #[test]
    fn test_parse_get_assertion_missing_rp_id() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x02), cbor_bytes(&[0xbb; 32]));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::MissingField("rpId"))));
    }

    #[test]
    fn test_parse_get_assertion_missing_client_data_hash() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("example.com"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::MissingField("clientDataHash"))
        ));
    }

    #[test]
    fn test_parse_get_assertion_allow_list_too_large() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("example.com"));
        map.insert(cbor_int(0x02), cbor_bytes(&[0xbb; 32]));

        let descriptors: Vec<Value> = (0..MAX_DESCRIPTOR_COUNT + 1)
            .map(|i| make_descriptor(&[i as u8; 32]))
            .collect();
        map.insert(cbor_int(0x03), Value::Array(descriptors));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::TooManyDescriptors)));
    }

    #[test]
    fn test_parse_get_assertion_invalid_rp_id() {
        let cbor_data = make_assertion_bytes("https://evil.com");
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::RpIdInvalid)));
    }

    #[test]
    fn test_parse_get_assertion_wrong_type_rp_id() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_int(42));
        map.insert(cbor_int(0x02), cbor_bytes(&[0xbb; 32]));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("rpId"))
        ));
    }

    #[test]
    fn test_parse_ceremony_request_empty() {
        assert_eq!(parse_ceremony_request(&[]), Err(CeremonyError::EmptyInput));
    }

    #[test]
    fn test_parse_ceremony_request_too_short() {
        assert_eq!(
            parse_ceremony_request(&[0x01]),
            Err(CeremonyError::CommandTooShort)
        );
    }

    #[test]
    fn test_parse_ceremony_request_wrong_command() {
        assert_eq!(
            parse_ceremony_request(&[0x04, 0xa0]),
            Err(CeremonyError::WrongCommand)
        );
    }

    #[test]
    fn test_parse_mc_response_uv_and_up_set() {
        let auth_data = make_auth_data(FLAG_UP | FLAG_UV);
        let raw = make_mc_response(&auth_data);

        let result = parse_ceremony_response(0x01, &raw, true).unwrap();
        match result {
            ParsedCeremonyResponse::MakeCredential(resp) => {
                assert_eq!(resp.auth_data, auth_data);
            }
            _ => panic!("expected MakeCredential response"),
        }
    }

    #[test]
    fn test_parse_mc_response_up_only_no_uv_required() {
        let auth_data = make_auth_data(FLAG_UP);
        let raw = make_mc_response(&auth_data);

        let result = parse_ceremony_response(0x01, &raw, false).unwrap();
        match result {
            ParsedCeremonyResponse::MakeCredential(resp) => {
                assert_eq!(resp.auth_data, auth_data);
            }
            _ => panic!("expected MakeCredential response"),
        }
    }

    #[test]
    fn test_parse_mc_response_up_not_set() {
        let auth_data = make_auth_data(FLAG_UV);
        let raw = make_mc_response(&auth_data);

        let result = parse_ceremony_response(0x01, &raw, true);
        assert!(matches!(result, Err(CeremonyError::UpNotSet)));
    }

    #[test]
    fn test_parse_ga_response_uv_and_up_set() {
        let auth_data = make_auth_data(FLAG_UP | FLAG_UV);
        let raw = make_ga_response(&auth_data);

        let result = parse_ceremony_response(0x02, &raw, true).unwrap();
        match result {
            ParsedCeremonyResponse::GetAssertion(resp) => {
                assert_eq!(resp.auth_data, auth_data);
            }
            _ => panic!("expected GetAssertion response"),
        }
    }

    #[test]
    fn test_parse_ga_response_up_not_set() {
        let auth_data = make_auth_data(0x00);
        let raw = make_ga_response(&auth_data);

        let result = parse_ceremony_response(0x02, &raw, true);
        assert!(matches!(result, Err(CeremonyError::UpNotSet)));
    }

    #[test]
    fn test_parse_response_auth_data_too_short() {
        let short_data = vec![0u8; 32];
        let raw = make_mc_response(&short_data);

        let result = parse_ceremony_response(0x01, &raw, true);
        assert!(matches!(result, Err(CeremonyError::AuthDataTooShort)));
    }

    #[test]
    fn test_parse_response_non_zero_status() {
        let auth_data = make_auth_data(FLAG_UP | FLAG_UV);
        let mut raw = make_mc_response(&auth_data);
        raw[0] = 0x01;

        let result = parse_ceremony_response(0x01, &raw, true);
        assert!(matches!(result, Err(CeremonyError::NonZeroStatus)));
    }

    #[test]
    fn test_parse_response_empty() {
        assert_eq!(
            parse_ceremony_response(0x01, &[], true),
            Err(CeremonyError::EmptyInput)
        );
    }

    #[test]
    fn test_parse_response_wrong_command() {
        let auth_data = make_auth_data(FLAG_UP | FLAG_UV);
        let raw = make_mc_response(&auth_data);

        let result = parse_ceremony_response(0x04, &raw, true);
        assert!(matches!(result, Err(CeremonyError::WrongCommand)));
    }

    #[test]
    fn test_parse_response_malformed_cbor() {
        let raw = vec![0x00, 0xff, 0xff];

        let result = parse_ceremony_response(0x01, &raw, true);
        assert!(matches!(result, Err(CeremonyError::InvalidCbor)));
    }

    #[test]
    fn test_parse_response_missing_auth_data() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("none"));
        map.insert(cbor_int(0x03), Value::Map(vec![].into_iter().collect()));
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());

        let result = parse_ceremony_response(0x01, &raw, true);
        assert!(matches!(result, Err(CeremonyError::MalformedResponse)));
    }

    #[test]
    fn test_parse_ga_response_missing_credential() {
        let auth_data = make_auth_data(FLAG_UP | FLAG_UV);
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x02), cbor_bytes(&auth_data));
        map.insert(cbor_int(0x03), cbor_bytes(&[0xdd; 64]));
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());

        let result = parse_ceremony_response(0x02, &raw, true);
        assert!(matches!(result, Err(CeremonyError::MalformedResponse)));
    }

    #[test]
    fn test_parse_ga_response_missing_signature() {
        let auth_data = make_auth_data(FLAG_UP | FLAG_UV);
        let mut cred_desc = std::collections::BTreeMap::new();
        cred_desc.insert(cbor_text("id"), cbor_bytes(&[0xcc; 32]));
        cred_desc.insert(cbor_text("type"), cbor_text("public-key"));

        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), Value::Map(cred_desc.into_iter().collect()));
        map.insert(cbor_int(0x02), cbor_bytes(&auth_data));
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());

        let result = parse_ceremony_response(0x02, &raw, true);
        assert!(matches!(result, Err(CeremonyError::MalformedResponse)));
    }

    #[test]
    fn test_validate_rp_id_valid() {
        assert_eq!(validate_rp_id("example.com").unwrap(), "example.com");
        assert_eq!(
            validate_rp_id("sub.example.com").unwrap(),
            "sub.example.com"
        );
        assert_eq!(validate_rp_id("EXAMPLE.COM").unwrap(), "example.com");
        assert_eq!(validate_rp_id("  Example.COM  ").unwrap(), "example.com");
    }

    #[test]
    fn test_validate_rp_id_rejects_empty() {
        assert_eq!(validate_rp_id(""), Err(CeremonyError::RpIdEmpty));
        assert_eq!(validate_rp_id("   "), Err(CeremonyError::RpIdEmpty));
    }

    #[test]
    fn test_validate_rp_id_rejects_too_long() {
        let long = format!("{}.com", "a".repeat(MAX_RP_ID_LEN));
        assert_eq!(validate_rp_id(&long), Err(CeremonyError::RpIdTooLong));
    }

    #[test]
    fn test_validate_rp_id_rejects_scheme() {
        assert_eq!(
            validate_rp_id("https://example.com"),
            Err(CeremonyError::RpIdInvalid)
        );
    }

    #[test]
    fn test_validate_rp_id_rejects_path() {
        assert_eq!(
            validate_rp_id("example.com/path"),
            Err(CeremonyError::RpIdInvalid)
        );
    }

    #[test]
    fn test_validate_rp_id_rejects_port() {
        assert_eq!(
            validate_rp_id("example.com:443"),
            Err(CeremonyError::RpIdInvalid)
        );
    }

    #[test]
    fn test_validate_rp_id_rejects_wildcard() {
        assert_eq!(
            validate_rp_id("*.example.com"),
            Err(CeremonyError::RpIdInvalid)
        );
    }

    #[test]
    fn test_validate_rp_id_rejects_trailing_dot() {
        assert_eq!(
            validate_rp_id("example.com."),
            Err(CeremonyError::RpIdInvalid)
        );
    }

    #[test]
    fn test_validate_rp_id_rejects_single_label() {
        assert_eq!(validate_rp_id("localhost"), Err(CeremonyError::RpIdInvalid));
        assert_eq!(validate_rp_id("com"), Err(CeremonyError::RpIdInvalid));
    }

    #[test]
    fn test_validate_rp_id_rejects_empty_label() {
        assert_eq!(
            validate_rp_id("example..com"),
            Err(CeremonyError::RpIdInvalid)
        );
    }

    #[test]
    fn test_validate_rp_id_rejects_label_too_long() {
        let long_label = format!("{}.com", "a".repeat(64));
        assert_eq!(validate_rp_id(&long_label), Err(CeremonyError::RpIdInvalid));
    }

    #[test]
    fn test_validate_rp_id_rejects_label_starting_with_dash() {
        assert_eq!(
            validate_rp_id("-example.com"),
            Err(CeremonyError::RpIdInvalid)
        );
    }

    #[test]
    fn test_validate_rp_id_rejects_label_ending_with_dash() {
        assert_eq!(
            validate_rp_id("example-.com"),
            Err(CeremonyError::RpIdInvalid)
        );
    }

    #[test]
    fn test_validate_rp_id_rejects_invalid_chars() {
        assert_eq!(
            validate_rp_id("exam ple.com"),
            Err(CeremonyError::RpIdInvalid)
        );
        assert_eq!(
            validate_rp_id("exam_ple.com"),
            Err(CeremonyError::RpIdInvalid)
        );
    }

    #[test]
    fn test_verify_auth_data_flags_up_set() {
        let data = make_auth_data(FLAG_UP);
        assert!(verify_auth_data_flags(&data, false).is_ok());
    }

    #[test]
    fn test_verify_auth_data_flags_up_and_uv_set() {
        let data = make_auth_data(FLAG_UP | FLAG_UV);
        assert!(verify_auth_data_flags(&data, true).is_ok());
    }

    #[test]
    fn test_verify_auth_data_flags_up_not_set() {
        let data = make_auth_data(0x00);
        assert_eq!(
            verify_auth_data_flags(&data, false),
            Err(CeremonyError::UpNotSet)
        );
    }

    #[test]
    fn test_verify_auth_data_flags_uv_required_but_not_set() {
        let data = make_auth_data(FLAG_UP);
        assert_eq!(
            verify_auth_data_flags(&data, true),
            Err(CeremonyError::UvNotSet)
        );
    }

    #[test]
    fn test_verify_auth_data_flags_uv_not_required_and_not_set() {
        let data = make_auth_data(FLAG_UP);
        assert!(verify_auth_data_flags(&data, false).is_ok());
    }

    #[test]
    fn test_verify_auth_data_flags_too_short() {
        let data = vec![0u8; 32];
        assert_eq!(
            verify_auth_data_flags(&data, false),
            Err(CeremonyError::AuthDataTooShort)
        );
    }

    #[test]
    fn test_verify_auth_data_flags_empty() {
        assert_eq!(
            verify_auth_data_flags(&[], false),
            Err(CeremonyError::AuthDataTooShort)
        );
    }

    #[test]
    fn test_verify_auth_data_flags_exact_min_length() {
        let data = make_auth_data(FLAG_UP | FLAG_UV);
        assert_eq!(data.len(), AUTH_DATA_MIN_LEN);
        assert!(verify_auth_data_flags(&data, true).is_ok());
    }

    #[test]
    fn test_verify_auth_data_flags_with_extensions() {
        let mut data = vec![0u8; 50];
        data[32] = FLAG_UP | FLAG_UV;
        assert!(verify_auth_data_flags(&data, true).is_ok());
    }

    #[test]
    fn test_has_duplicate_keys_no_duplicates() {
        let map_data = cbor_map(vec![
            (cbor_int(1), cbor_text("a")),
            (cbor_int(2), cbor_text("b")),
        ]);
        assert!(!has_duplicate_keys(&map_data).unwrap());
    }

    #[test]
    fn test_has_duplicate_keys_with_duplicates() {
        let raw = [0xa2, 0x01, 0x61, b'a', 0x01, 0x61, b'b'];
        assert!(has_duplicate_keys(&raw).unwrap());
    }

    #[test]
    fn test_has_duplicate_keys_empty_map() {
        let map_data = cbor_map(vec![]);
        assert!(!has_duplicate_keys(&map_data).unwrap());
    }

    #[test]
    fn test_has_duplicate_keys_single_entry() {
        let map_data = cbor_map(vec![(cbor_int(1), cbor_text("a"))]);
        assert!(!has_duplicate_keys(&map_data).unwrap());
    }

    #[test]
    fn test_has_duplicate_keys_not_a_map() {
        let data = cbor::to_vec(&cbor_text("hello")).unwrap();
        assert!(!has_duplicate_keys(&data).unwrap());
    }

    #[test]
    fn test_has_duplicate_keys_empty_input() {
        assert!(!has_duplicate_keys(&[]).unwrap());
    }

    #[test]
    fn test_has_duplicate_keys_rejects_indefinite_map() {
        assert_eq!(
            has_duplicate_keys(&[0xbf, 0xff]),
            Err(CeremonyError::InvalidCbor)
        );
    }

    #[test]
    fn test_fuzz_empty_input() {
        assert_eq!(parse_ceremony_request(&[]), Err(CeremonyError::EmptyInput));
    }

    #[test]
    fn test_fuzz_single_byte() {
        for b in 0..=255u8 {
            let result = parse_ceremony_request(&[b]);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_fuzz_random_bytes_make_credential() {
        let inputs: Vec<Vec<u8>> = vec![
            vec![0x01, 0x00],
            vec![0x01, 0x80],
            vec![0x01, 0xa0],
            vec![0x01, 0xff],
            vec![0x01, 0x60],
            vec![0x01, 0x40],
            vec![0x01, 0xf6],
            vec![0x01, 0xf7],
        ];
        for input in inputs {
            assert!(parse_ceremony_request(&input).is_err());
        }
    }

    #[test]
    fn test_fuzz_random_bytes_get_assertion() {
        let inputs: Vec<Vec<u8>> = vec![
            vec![0x02, 0x00],
            vec![0x02, 0x80],
            vec![0x02, 0xa0],
            vec![0x02, 0xff],
            vec![0x02, 0x60],
            vec![0x02, 0x40],
        ];
        for input in inputs {
            assert!(parse_ceremony_request(&input).is_err());
        }
    }

    #[test]
    fn test_fuzz_truncated_cbor() {
        let full = make_credential_bytes("example.com");
        for truncate_at in 1..full.len() {
            let mut raw = vec![0x01];
            raw.extend_from_slice(&full[..truncate_at]);
            assert!(parse_ceremony_request(&raw).is_err());
        }
    }

    #[test]
    fn test_fuzz_response_empty() {
        assert_eq!(
            parse_ceremony_response(0x01, &[], true),
            Err(CeremonyError::EmptyInput)
        );
    }

    #[test]
    fn test_fuzz_response_single_byte_non_zero() {
        for b in 1..=255u8 {
            assert_eq!(
                parse_ceremony_response(0x01, &[b], true),
                Err(CeremonyError::NonZeroStatus)
            );
        }
    }

    #[test]
    fn test_fuzz_response_truncated_auth_data() {
        for len in 0..AUTH_DATA_MIN_LEN {
            let auth_data = vec![FLAG_UP | FLAG_UV; len];
            let raw = make_mc_response(&auth_data);
            let result = parse_ceremony_response(0x01, &raw, true);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_fuzz_response_random_cbor() {
        let bad_cbor_inputs: Vec<Vec<u8>> = vec![
            vec![0x00, 0xff],
            vec![0x00, 0x80],
            vec![0x00, 0x40],
            vec![0x00, 0x60],
            vec![0x00, 0xa0],
        ];
        for input in bad_cbor_inputs {
            assert!(parse_ceremony_response(0x01, &input, true).is_err());
        }
    }

    #[test]
    fn test_fixture_make_credential_minimal() {
        let cbor_bytes = [
            0xa3, 0x01, 0x58, 0x20, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x02, 0xa1, 0x62, 0x69, 0x64, 0x6b,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x04, 0x81, 0xa2,
            0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b,
            0x65, 0x79, 0x63, 0x61, 0x6c, 0x67, 0x26,
        ];

        let mut raw = vec![0x01];
        raw.extend_from_slice(&cbor_bytes);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::MakeCredential(mc) => {
                assert_eq!(mc.rp_id, "example.com");
                assert!(!mc.require_uv);
                assert!(mc.exclude_refs.is_empty());
            }
            _ => panic!("expected MakeCredential"),
        }
    }

    #[test]
    fn test_fixture_get_assertion_minimal() {
        let cbor_bytes = [
            0xa2, 0x01, 0x6b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
            0x02, 0x58, 0x20, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
            0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
            0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
        ];

        let mut raw = vec![0x02];
        raw.extend_from_slice(&cbor_bytes);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::GetAssertion(ga) => {
                assert_eq!(ga.rp_id, "example.com");
                assert!(!ga.require_uv);
                assert!(ga.allow_refs.is_empty());
            }
            _ => panic!("expected GetAssertion"),
        }
    }

    #[test]
    fn test_error_display() {
        assert_eq!(CeremonyError::EmptyInput.to_string(), "empty input");
        assert_eq!(
            CeremonyError::InvalidCbor.to_string(),
            "invalid CBOR encoding"
        );
        assert_eq!(
            CeremonyError::MissingField("rp").to_string(),
            "missing required field: rp"
        );
        assert_eq!(
            CeremonyError::RpIdInvalid.to_string(),
            "RP ID is not a valid domain"
        );
        assert_eq!(CeremonyError::UpNotSet.to_string(), "UP flag not set");
        assert_eq!(CeremonyError::UvNotSet.to_string(), "UV flag not set");
    }

    #[test]
    fn test_constants_are_correct() {
        assert_eq!(CMD_MAKE_CREDENTIAL, 0x01);
        assert_eq!(CMD_GET_ASSERTION, 0x02);
        assert_eq!(CMD_GET_INFO, 0x04);
        assert_eq!(CMD_CLIENT_PIN, 0x06);
        assert_eq!(CMD_RESET, 0x07);
        assert_eq!(CMD_CREDENTIAL_MGMT, 0x0A);
        assert_eq!(CMD_SELECTION, 0x0B);
        assert_eq!(CMD_VENDOR_FIRST, 0x40);
        assert_eq!(CMD_VENDOR_LAST, 0xBF);
        assert_eq!(CTAP_OK, 0x00);
        assert_eq!(AUTH_DATA_MIN_LEN, 37);
        assert_eq!(AUTH_DATA_FLAGS_OFFSET, 32);
        assert_eq!(FLAG_UP, 0x01);
        assert_eq!(FLAG_UV, 0x04);
        assert_eq!(MAX_CREDENTIAL_ID_SIZE, 256);
        assert_eq!(MAX_DESCRIPTOR_COUNT, 16);
        assert_eq!(MAX_RP_ID_LEN, 253);
    }

    #[test]
    fn test_credential_id_boundary_max_size() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(
            cbor_int(0x05),
            Value::Array(vec![make_descriptor(&[0xaa; MAX_CREDENTIAL_ID_SIZE])]),
        );

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::MakeCredential(mc) => {
                assert_eq!(mc.exclude_refs.len(), 1);
            }
            _ => panic!("expected MakeCredential"),
        }
    }

    #[test]
    fn test_credential_id_empty_rejected() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(cbor_int(0x05), Value::Array(vec![make_descriptor(&[])]));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::CredentialIdTooLarge)));
    }

    #[test]
    fn test_descriptor_count_boundary_max() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );

        let descriptors: Vec<Value> = (0..MAX_DESCRIPTOR_COUNT)
            .map(|i| make_descriptor(&[i as u8; 32]))
            .collect();
        map.insert(cbor_int(0x05), Value::Array(descriptors));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::MakeCredential(mc) => {
                assert_eq!(mc.exclude_refs.len(), MAX_DESCRIPTOR_COUNT);
            }
            _ => panic!("expected MakeCredential"),
        }
    }

    #[test]
    fn test_options_uv_false_explicit() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        let mut opts = std::collections::BTreeMap::new();
        opts.insert(cbor_text("uv"), cbor_bool(false));
        map.insert(cbor_int(0x07), Value::Map(opts.into_iter().collect()));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw).unwrap();
        match result {
            ParsedCeremonyRequest::MakeCredential(mc) => {
                assert!(!mc.require_uv);
            }
            _ => panic!("expected MakeCredential"),
        }
    }

    #[test]
    fn test_options_wrong_type_rejected() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(cbor_int(0x07), cbor_text("not-a-map"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("options"))
        ));
    }

    #[test]
    fn test_rp_id_missing_id_field() {
        let rp_map = Value::Map(
            vec![(cbor_text("name"), cbor_text("Example"))]
                .into_iter()
                .collect(),
        );
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), rp_map);
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(result, Err(CeremonyError::MissingField("rp.id"))));
    }

    #[test]
    fn test_rp_id_wrong_type() {
        let rp_map = Value::Map(vec![(cbor_text("id"), cbor_int(42))].into_iter().collect());
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), rp_map);
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("rp.id"))
        ));
    }

    #[test]
    fn test_exclude_list_wrong_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(cbor_int(0x05), cbor_text("not-a-list"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("excludeList"))
        ));
    }

    #[test]
    fn test_allow_list_wrong_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("example.com"));
        map.insert(cbor_int(0x02), cbor_bytes(&[0xbb; 32]));
        map.insert(cbor_int(0x03), cbor_int(42));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("allowList"))
        ));
    }

    #[test]
    fn test_extensions_wrong_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(cbor_int(0x06), cbor_text("not-a-map"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("extensions"))
        ));
    }

    #[test]
    fn test_pin_uv_auth_param_wrong_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(cbor_int(0x08), cbor_text("not-bytes"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("pinUvAuthParam"))
        ));
    }

    #[test]
    fn test_enterprise_attestation_wrong_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(cbor_int(0x09), cbor_text("not-int"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("enterpriseAttestation"))
        ));
    }

    #[test]
    fn test_ga_pin_uv_auth_protocol_wrong_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("example.com"));
        map.insert(cbor_int(0x02), cbor_bytes(&[0xbb; 32]));
        map.insert(cbor_int(0x07), cbor_text("not-int"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("pinUvAuthProtocol"))
        ));
    }

    #[test]
    fn test_descriptor_missing_id_field() {
        let desc = Value::Map(
            vec![(cbor_text("type"), cbor_text("public-key"))]
                .into_iter()
                .collect(),
        );
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(cbor_int(0x05), Value::Array(vec![desc]));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::MissingField("descriptor.id"))
        ));
    }

    #[test]
    fn test_descriptor_id_wrong_type() {
        let desc = Value::Map(
            vec![
                (cbor_text("id"), cbor_text("not-bytes")),
                (cbor_text("type"), cbor_text("public-key")),
            ]
            .into_iter()
            .collect(),
        );
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(cbor_int(0x05), Value::Array(vec![desc]));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("descriptor.id"))
        ));
    }

    #[test]
    fn test_descriptor_not_a_map() {
        let desc = cbor_text("not-a-map");
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(cbor_int(0x05), Value::Array(vec![desc]));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("descriptor"))
        ));
    }

    #[test]
    fn test_command_class_exhaustive_ceremony() {
        let ceremony_cmds = [0x01, 0x02];
        for cmd in ceremony_cmds {
            assert_eq!(classify_command(cmd), CommandClass::Ceremony);
        }
    }

    #[test]
    fn test_command_class_exhaustive_safe() {
        let safe_cmds = [0x04, 0x06, 0x0b];
        for cmd in safe_cmds {
            assert_eq!(classify_command(cmd), CommandClass::SafeNonCeremony);
        }
    }

    #[test]
    fn test_command_class_exhaustive_denied() {
        let denied_cmds = [0x07, 0x0a];
        for cmd in denied_cmds {
            assert_eq!(classify_command(cmd), CommandClass::Denied);
        }
        for cmd in 0x40..=0xBF {
            assert_eq!(classify_command(cmd), CommandClass::Denied);
        }
    }

    #[test]
    fn test_parse_mc_response_not_a_map() {
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Array(vec![])).unwrap());

        let result = parse_ceremony_response(0x01, &raw, true);
        assert!(matches!(result, Err(CeremonyError::MalformedResponse)));
    }

    #[test]
    fn test_parse_ga_response_not_a_map() {
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Array(vec![])).unwrap());

        let result = parse_ceremony_response(0x02, &raw, true);
        assert!(matches!(result, Err(CeremonyError::MalformedResponse)));
    }

    #[test]
    fn test_parse_mc_response_missing_format() {
        let auth_data = make_auth_data(FLAG_UP | FLAG_UV);
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x02), cbor_bytes(&auth_data));
        map.insert(cbor_int(0x03), Value::Map(vec![].into_iter().collect()));
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());

        let result = parse_ceremony_response(0x01, &raw, true);
        assert!(matches!(result, Err(CeremonyError::MalformedResponse)));
    }

    #[test]
    fn test_parse_mc_response_missing_att_stmt() {
        let auth_data = make_auth_data(FLAG_UP | FLAG_UV);
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("none"));
        map.insert(cbor_int(0x02), cbor_bytes(&auth_data));
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());

        let result = parse_ceremony_response(0x01, &raw, true);
        assert!(matches!(result, Err(CeremonyError::MalformedResponse)));
    }

    #[test]
    fn test_parse_mc_response_auth_data_wrong_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("none"));
        map.insert(cbor_int(0x02), cbor_text("not-bytes"));
        map.insert(cbor_int(0x03), Value::Map(vec![].into_iter().collect()));
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());

        let result = parse_ceremony_response(0x01, &raw, true);
        assert!(matches!(result, Err(CeremonyError::MalformedResponse)));
    }

    #[test]
    fn test_parse_ga_response_auth_data_wrong_type() {
        let mut cred_desc = std::collections::BTreeMap::new();
        cred_desc.insert(cbor_text("id"), cbor_bytes(&[0xcc; 32]));
        cred_desc.insert(cbor_text("type"), cbor_text("public-key"));

        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), Value::Map(cred_desc.into_iter().collect()));
        map.insert(cbor_int(0x02), cbor_text("not-bytes"));
        map.insert(cbor_int(0x03), cbor_bytes(&[0xdd; 64]));
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());

        let result = parse_ceremony_response(0x02, &raw, true);
        assert!(matches!(result, Err(CeremonyError::MalformedResponse)));
    }

    #[test]
    fn test_parse_ga_response_signature_wrong_type() {
        let auth_data = make_auth_data(FLAG_UP | FLAG_UV);
        let mut cred_desc = std::collections::BTreeMap::new();
        cred_desc.insert(cbor_text("id"), cbor_bytes(&[0xcc; 32]));
        cred_desc.insert(cbor_text("type"), cbor_text("public-key"));

        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), Value::Map(cred_desc.into_iter().collect()));
        map.insert(cbor_int(0x02), cbor_bytes(&auth_data));
        map.insert(cbor_int(0x03), cbor_text("not-bytes"));
        let mut raw = vec![0x00];
        raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());

        let result = parse_ceremony_response(0x02, &raw, true);
        assert!(matches!(result, Err(CeremonyError::MalformedResponse)));
    }

    #[test]
    fn test_malformed_truncated_cbor() {
        let mut raw = vec![0x01];
        raw.extend_from_slice(&[0xa3, 0x01, 0x6b]);

        let result = parse_ceremony_request(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_indefinite_length_not_supported() {
        let mut raw = vec![0x01];
        raw.extend_from_slice(&[0xbf, 0xff]);

        let result = parse_ceremony_request(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_user_field_wrong_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_bytes(&[0xaa; 32]));
        map.insert(cbor_int(0x02), make_rp_entity("example.com"));
        map.insert(
            cbor_int(0x04),
            Value::Array(vec![{
                let mut m = std::collections::BTreeMap::new();
                m.insert(cbor_text("type"), cbor_text("public-key"));
                m.insert(cbor_text("alg"), Value::Integer(-7));
                Value::Map(m.into_iter().collect())
            }]),
        );
        map.insert(cbor_int(0x03), cbor_text("not-a-map"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x01];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("user"))
        ));
    }

    #[test]
    fn test_ga_extensions_wrong_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("example.com"));
        map.insert(cbor_int(0x02), cbor_bytes(&[0xbb; 32]));
        map.insert(cbor_int(0x04), cbor_text("not-a-map"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("extensions"))
        ));
    }

    #[test]
    fn test_ga_pin_uv_auth_param_wrong_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(0x01), cbor_text("example.com"));
        map.insert(cbor_int(0x02), cbor_bytes(&[0xbb; 32]));
        map.insert(cbor_int(0x06), cbor_text("not-bytes"));

        let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
        let mut raw = vec![0x02];
        raw.extend(cbor_data);

        let result = parse_ceremony_request(&raw);
        assert!(matches!(
            result,
            Err(CeremonyError::InvalidFieldType("pinUvAuthParam"))
        ));
    }

    #[test]
    fn test_valid_subdomain_rp_id() {
        assert_eq!(
            validate_rp_id("sub.domain.example.com").unwrap(),
            "sub.domain.example.com"
        );
    }

    #[test]
    fn test_rp_id_with_hyphens() {
        assert_eq!(
            validate_rp_id("my-site.example.com").unwrap(),
            "my-site.example.com"
        );
    }

    #[test]
    fn test_rp_id_with_numbers() {
        assert_eq!(
            validate_rp_id("site123.example.com").unwrap(),
            "site123.example.com"
        );
    }

    #[test]
    fn test_command_debug_format() {
        let cmd = Command::MakeCredential;
        let debug = format!("{:?}", cmd);
        assert!(debug.contains("MakeCredential"));
    }

    #[test]
    fn test_ceremony_error_debug_format() {
        let err = CeremonyError::InvalidCbor;
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidCbor"));
    }

    #[test]
    fn test_parsed_request_debug() {
        let mc = ParsedMakeCredential {
            rp_id: "example.com".to_string(),
            require_uv: false,
            exclude_refs: vec![],
        };
        let req = ParsedCeremonyRequest::MakeCredential(mc);
        let debug = format!("{:?}", req);
        assert!(debug.contains("MakeCredential"));
        assert!(debug.contains("example.com"));
    }

    #[test]
    fn test_command_class_debug() {
        let cc = CommandClass::Ceremony;
        let debug = format!("{:?}", cc);
        assert!(debug.contains("Ceremony"));
    }

    mod handler_tests {
        #![allow(clippy::arc_with_non_send_sync)]

        use super::*;
        use crate::agent::audit::AuditGate;
        use crate::agent::browser::Clock;
        use crate::agent::intent::{MonotonicClock, MonotonicTime, ProcessIdentityDigest};
        use crate::agent::policy_engine::PolicyRuntime;
        use crate::agent::prompt::AutoApproveHandle;
        use crate::agent::storage::CeremonyScope;
        use passless_core::agent::{
            AgentConfig, AgentMode, AgentProfileConfig, AgentStorageConfig, CredentialRef,
            DeviceIdentity, EndpointId, PolicyDigest, PolicyGenerationId, PrincipalSessionId,
            ProfileId,
        };
        use std::collections::BTreeMap;
        use std::path::PathBuf;
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        use passless_core::agent::protocol::IntentAction;

        struct FakeHandler {
            calls: Arc<Mutex<Vec<Vec<u8>>>>,
            response: Vec<u8>,
        }

        impl FakeHandler {
            fn new(response: Vec<u8>) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
                let calls = Arc::new(Mutex::new(Vec::new()));
                (
                    Self {
                        calls: calls.clone(),
                        response,
                    },
                    calls,
                )
            }
        }

        impl soft_fido2_transport::CommandHandler for FakeHandler {
            fn handle_command(
                &mut self,
                _cmd: soft_fido2_transport::Cmd,
                data: &[u8],
            ) -> soft_fido2_transport::Result<Vec<u8>> {
                self.calls.lock().unwrap().push(data.to_vec());
                Ok(self.response.clone())
            }
        }

        struct FakeErroringHandler;

        impl soft_fido2_transport::CommandHandler for FakeErroringHandler {
            fn handle_command(
                &mut self,
                _cmd: soft_fido2_transport::Cmd,
                _data: &[u8],
            ) -> soft_fido2_transport::Result<Vec<u8>> {
                Ok(vec![0x01])
            }
        }

        struct MockClock {
            inner: Mutex<MockInner>,
        }

        struct MockInner {
            base: Instant,
            offset: Duration,
        }

        impl MockClock {
            fn new() -> Self {
                Self {
                    inner: Mutex::new(MockInner {
                        base: Instant::now(),
                        offset: Duration::ZERO,
                    }),
                }
            }
        }

        impl Clock for MockClock {
            fn now(&self) -> Instant {
                let inner = self.inner.lock().unwrap();
                inner.base + inner.offset
            }

            fn monotonic_secs(&self) -> u64 {
                self.inner.lock().unwrap().offset.as_secs()
            }
        }

        impl MonotonicClock for MockClock {
            fn now(&self) -> MonotonicTime {
                MonotonicTime::from_millis(self.inner.lock().unwrap().offset.as_millis() as u64)
            }
        }

        fn test_device() -> DeviceIdentity {
            DeviceIdentity {
                name: "test-agent".to_string(),
                phys: "test-phys".to_string(),
                uniq: "test-uniq".to_string(),
                vendor_id: 0x1234,
                product_id: 0x5678,
            }
        }

        fn make_isolated_config(registration_allowed: bool) -> AgentConfig {
            let mut profiles = BTreeMap::new();
            profiles.insert(
                "test".to_string(),
                AgentProfileConfig {
                    max_operations: 64,
                    credential_selection: passless_core::agent::config::CredentialSelection::Single,
                    human_verification_prompt:
                        passless_core::agent::config::HumanVerificationPrompt::Always,
                    mode: AgentMode::Isolated,
                    principal_user: "test-user".to_string(),
                    rp_ids: vec!["example.com".to_string()],
                    require_uv: false,
                    credential_refs: None,
                    max_grant_ttl: None,
                    max_session_ttl: None,
                    storage: Some(AgentStorageConfig::Local {
                        path: PathBuf::from("/tmp/test-handler/creds"),
                        pin_path: PathBuf::from("/tmp/test-handler/pin"),
                    }),
                    registration_allowed,
                    rules: vec![],
                    device: test_device(),
                    start_url: None,
                    browser_command: None,
                    browser_user: None,
                    browser_runtime_root: None,
                    browser_cdp_expose: None,
                    browser_cdp_port: None,
                },
            );
            AgentConfig {
                enabled: true,
                profiles,
                audit_path: Some(PathBuf::from("/tmp/test-handler-audit")),
            }
        }

        fn make_runtime() -> (Arc<PolicyRuntime>, Arc<AuditGate>) {
            let suffix = format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            make_runtime_with_suffix(&suffix)
        }

        fn make_runtime_with_suffix(suffix: &str) -> (Arc<PolicyRuntime>, Arc<AuditGate>) {
            let clock = Arc::new(MockClock::new());
            let config = make_isolated_config(true);
            let runtime =
                Arc::new(PolicyRuntime::new(&config, clock.clone(), clock.clone()).unwrap());

            let audit_dir = format!("/tmp/test-handler-audit-{}", suffix);
            let _ = std::fs::remove_dir_all(&audit_dir);
            let _ = std::fs::create_dir_all(&audit_dir);
            let _ = std::fs::set_permissions(
                &audit_dir,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            );
            let audit = Arc::new(AuditGate::open(&audit_dir).unwrap());

            (runtime, audit)
        }

        #[allow(clippy::type_complexity)]
        fn make_handler(
            response: Vec<u8>,
        ) -> (
            AgentCeremonyHandler<FakeHandler>,
            Arc<Mutex<Vec<Vec<u8>>>>,
            Arc<PolicyRuntime>,
            Arc<CeremonyPreparationSlot>,
        ) {
            let (runtime, audit) = make_runtime();
            let generation = runtime.current_generation();
            let profile_id = ProfileId::new("test").unwrap();
            let session_id = PrincipalSessionId::new();
            let endpoint_id = EndpointId::new();
            let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");

            let slot = Arc::new(CeremonyPreparationSlot::new());

            let scope = CeremonyScope::new();
            let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                profile_id,
                endpoint_id,
                mode: PromptMode::Isolated,
                policy_runtime: runtime.clone(),
                audit_gate: audit,
                ceremony_scope: scope,
                require_uv: false,
                prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                preparation_slot: slot.clone(),
            });

            let _guard = slot
                .install(CeremonyPreparationInput {
                    session_id,
                    process_digest,
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Register,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();
            _guard.disarm();

            let (fake, calls) = FakeHandler::new(response);
            let handler = AgentCeremonyHandler::new(fake, ctx);
            (handler, calls, runtime, slot)
        }

        fn make_mc_request(rp_id: &str) -> Vec<u8> {
            let mut map = std::collections::BTreeMap::new();
            map.insert(Value::Integer(0x01), Value::Bytes(vec![0xaa; 32]));
            let mut rp_map = std::collections::BTreeMap::new();
            rp_map.insert(
                Value::Text("id".to_string()),
                Value::Text(rp_id.to_string()),
            );
            map.insert(
                Value::Integer(0x02),
                Value::Map(rp_map.into_iter().collect()),
            );
            map.insert(
                Value::Integer(0x04),
                Value::Array(vec![{
                    let mut m = std::collections::BTreeMap::new();
                    m.insert(
                        Value::Text("type".to_string()),
                        Value::Text("public-key".to_string()),
                    );
                    m.insert(Value::Text("alg".to_string()), Value::Integer(-7));
                    Value::Map(m.into_iter().collect())
                }]),
            );
            let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
            let mut raw = vec![0x01];
            raw.extend(cbor_data);
            raw
        }

        fn make_mc_response_bytes() -> Vec<u8> {
            let mut auth_data = vec![0u8; 37];
            auth_data[32] = FLAG_UP | FLAG_UV;

            let mut map = std::collections::BTreeMap::new();
            map.insert(Value::Integer(0x01), Value::Text("none".to_string()));
            map.insert(Value::Integer(0x02), Value::Bytes(auth_data));
            map.insert(
                Value::Integer(0x03),
                Value::Map(vec![].into_iter().collect()),
            );
            let mut raw = vec![0x00];
            raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());
            raw
        }

        #[test]
        fn test_handler_denied_command_class() {
            let (mut handler, calls, _, _) = make_handler(make_mc_response_bytes());
            let result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &[0x07])
                .unwrap();
            assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
            assert!(calls.lock().unwrap().is_empty());
        }

        #[test]
        fn test_handler_safe_non_ceremony_passthrough() {
            let (mut handler, calls, _, _) = make_handler(vec![0x00, 0xa0]);
            let result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &[0x04, 0xa0])
                .unwrap();
            assert_eq!(result, vec![0x00, 0xa0]);
            assert_eq!(calls.lock().unwrap().len(), 1);
        }

        #[test]
        fn test_handler_empty_input() {
            let (mut handler, calls, _, _) = make_handler(make_mc_response_bytes());
            let result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &[])
                .unwrap();
            assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
            assert!(calls.lock().unwrap().is_empty());
        }

        #[test]
        fn test_handler_unknown_command() {
            let (mut handler, calls, _, _) = make_handler(make_mc_response_bytes());
            let result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &[0xff])
                .unwrap();
            assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
            assert!(calls.lock().unwrap().is_empty());
        }

        #[test]
        fn test_handler_get_next_assertion_denied() {
            let (mut handler, calls, _, _) = make_handler(make_mc_response_bytes());
            let result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &[0x08])
                .unwrap();
            assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
            assert!(calls.lock().unwrap().is_empty());
        }

        #[test]
        fn test_handler_ceremony_policy_denied_no_inner() {
            let (mut handler, calls, _, _) = make_handler(make_mc_response_bytes());
            let request = make_mc_request("evil.com");
            let result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                .unwrap();
            assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
            assert!(calls.lock().unwrap().is_empty());
        }

        #[test]
        fn test_handler_inner_error_returns_denied() {
            let (runtime, audit) = make_runtime();
            let generation = runtime.current_generation();
            let profile_id = ProfileId::new("test").unwrap();
            let endpoint_id = EndpointId::new();
            let slot = Arc::new(CeremonyPreparationSlot::new());
            let _guard = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Register,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();
            _guard.disarm();
            let scope = CeremonyScope::new();
            let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                profile_id,
                endpoint_id,
                mode: PromptMode::Isolated,
                policy_runtime: runtime.clone(),
                audit_gate: audit,
                ceremony_scope: scope,
                require_uv: false,
                prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                preparation_slot: slot,
            });
            let mut handler = AgentCeremonyHandler::new(FakeErroringHandler, ctx);

            let request = make_mc_request("example.com");
            let result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                .unwrap();
            assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
        }

        #[test]
        fn test_handler_require_uv_context() {
            let (runtime, audit) = make_runtime();
            let profile_id = ProfileId::new("test").unwrap();
            let endpoint_id = EndpointId::new();
            let slot = Arc::new(CeremonyPreparationSlot::new());
            let scope = CeremonyScope::new();
            let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                profile_id,
                endpoint_id,
                mode: PromptMode::Isolated,
                policy_runtime: runtime.clone(),
                audit_gate: audit,
                ceremony_scope: scope,
                require_uv: true,
                prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                preparation_slot: slot,
            });

            assert!(ctx.require_uv());
        }

        #[test]
        fn test_session_binding_accessors() {
            let session_id = PrincipalSessionId::new();
            let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
            let gen_id = PolicyGenerationId::new();
            let digest = PolicyDigest::from_bytes([0u8; 32]);

            let slot = Arc::new(CeremonyPreparationSlot::new());
            let guard = slot
                .install(CeremonyPreparationInput {
                    session_id: session_id.clone(),
                    process_digest: process_digest.clone(),
                    policy_generation: gen_id.clone(),
                    policy_digest: digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Register,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();

            let prep = slot.snapshot().unwrap();
            assert_eq!(prep.session_id(), &session_id);
            assert_eq!(prep.process_digest(), &process_digest);
            assert_eq!(prep.policy_generation(), &gen_id);
            assert_eq!(prep.policy_digest(), &digest);
            assert_eq!(prep.generation(), guard.generation());
            assert_eq!(prep.untrusted_metadata().rp_id(), "example.com");
        }

        #[test]
        fn test_context_accessors() {
            let (runtime, audit) = make_runtime();
            let generation = runtime.current_generation();
            let profile_id = ProfileId::new("test").unwrap();
            let endpoint_id = EndpointId::new();
            let cred_ref = CredentialRef::with_default_domain(b"test-cred");

            let slot = Arc::new(CeremonyPreparationSlot::new());
            let _guard = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: Some(cred_ref.clone()),
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Register,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();
            _guard.disarm();

            let scope = CeremonyScope::new();
            let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                profile_id: profile_id.clone(),
                endpoint_id: endpoint_id.clone(),
                mode: PromptMode::Isolated,
                policy_runtime: runtime,
                audit_gate: audit,
                ceremony_scope: scope,
                require_uv: true,
                prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                preparation_slot: slot,
            });

            assert_eq!(ctx.profile_id(), &profile_id);
            assert_eq!(ctx.endpoint_id(), &endpoint_id);
            assert!(ctx.require_uv());
            let prep = ctx.preparation_slot().snapshot().unwrap();
            assert!(prep.credential_ref().is_some());
            assert_eq!(prep.credential_ref().unwrap(), &cred_ref);
        }

        #[test]
        fn test_operation_denied_response() {
            let resp = operation_denied_response();
            assert_eq!(resp, vec![CTAP_ERR_OPERATION_DENIED]);
        }

        #[test]
        fn test_agent_ceremony_error_display() {
            assert_eq!(
                AgentCeremonyError::CommandClassDenied.to_string(),
                "command class denied"
            );
            assert_eq!(
                AgentCeremonyError::GetNextAssertionDenied.to_string(),
                "get next assertion denied"
            );
            assert!(
                AgentCeremonyError::PolicyDenied(ReasonCode::DefaultDeny)
                    .to_string()
                    .contains("policy denied")
            );
            assert_eq!(
                AgentCeremonyError::NoPreparation.to_string(),
                "no active ceremony preparation"
            );
            assert_eq!(
                AgentCeremonyError::PreparationStale.to_string(),
                "ceremony preparation generation stale"
            );
        }

        #[test]
        fn test_no_preparation_denies_ceremony() {
            let (runtime, audit) = make_runtime();
            let profile_id = ProfileId::new("test").unwrap();
            let endpoint_id = EndpointId::new();
            let slot = Arc::new(CeremonyPreparationSlot::new());
            let scope = CeremonyScope::new();
            let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                profile_id,
                endpoint_id,
                mode: PromptMode::Isolated,
                policy_runtime: runtime.clone(),
                audit_gate: audit,
                ceremony_scope: scope,
                require_uv: false,
                prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                preparation_slot: slot.clone(),
            });

            let (fake, calls) = FakeHandler::new(make_mc_response_bytes());
            let mut handler = AgentCeremonyHandler::new(fake, ctx);

            assert!(!slot.is_active());
            let request = make_mc_request("example.com");
            let result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                .unwrap();
            assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
            assert!(calls.lock().unwrap().is_empty());
        }

        #[test]
        fn test_one_active_preparation_max() {
            let (runtime, _audit) = make_runtime();
            let generation = runtime.current_generation();
            let slot = Arc::new(CeremonyPreparationSlot::new());

            let _guard1 = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Register,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();

            let result = slot.install(CeremonyPreparationInput {
                session_id: PrincipalSessionId::new(),
                process_digest: ProcessIdentityDigest::compute(1000, 1000, 43, b"test2"),
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                credential_ref: None,
                untrusted_metadata: BoundedUntrustedMetadata::new(
                    "other.com".to_string(),
                    IntentAction::Authenticate,
                    false,
                ),
                clamped_grant_ttl_secs: 300,
                clamped_session_ttl_secs: 3600,
                trusted_credential_label: None,
            });
            assert!(matches!(result, Err(PreparationError::AlreadyActive)));
        }

        #[test]
        fn test_cross_session_replacement() {
            let (runtime, _audit) = make_runtime();
            let generation = runtime.current_generation();
            let slot = Arc::new(CeremonyPreparationSlot::new());

            let guard1 = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Register,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();
            let gen1 = guard1.generation();
            assert_eq!(gen1, 1);

            slot.clear_matching(gen1);
            assert!(!slot.is_active());

            let guard2 = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 43, b"test2"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "other.com".to_string(),
                        IntentAction::Authenticate,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();
            let gen2 = guard2.generation();
            assert_eq!(gen2, 2);
            assert!(slot.is_active());

            std::mem::forget(guard1);
        }

        #[test]
        fn test_stale_guard_does_not_clear() {
            let slot = Arc::new(CeremonyPreparationSlot::new());
            let (runtime, _audit) = make_runtime();
            let generation = runtime.current_generation();

            let guard1 = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Register,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();
            let gen1 = guard1.generation();
            guard1.disarm();

            slot.clear_matching(gen1);
            assert!(!slot.is_active());

            let _guard2 = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 43, b"test2"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "other.com".to_string(),
                        IntentAction::Authenticate,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();

            slot.clear_matching(gen1);
            assert!(slot.is_active());
        }

        #[test]
        fn test_terminal_clearing_after_success() {
            let (runtime, audit) = make_runtime();
            let generation = runtime.current_generation();
            let profile_id = ProfileId::new("test").unwrap();
            let endpoint_id = EndpointId::new();
            let slot = Arc::new(CeremonyPreparationSlot::new());
            let _guard = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Register,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();
            _guard.disarm();

            let scope = CeremonyScope::new();
            let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                profile_id,
                endpoint_id,
                mode: PromptMode::Isolated,
                policy_runtime: runtime.clone(),
                audit_gate: audit,
                ceremony_scope: scope,
                require_uv: false,
                prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                preparation_slot: slot.clone(),
            });

            let (fake, _calls) = FakeHandler::new(make_mc_response_bytes());
            let mut handler = AgentCeremonyHandler::new(fake, ctx);

            assert!(slot.is_active());
            let request = make_mc_request("example.com");
            let _result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                .unwrap();
            assert!(!slot.is_active());
        }

        #[test]
        fn test_safe_getinfo_preserves_preparation() {
            let (runtime, audit) = make_runtime();
            let generation = runtime.current_generation();
            let profile_id = ProfileId::new("test").unwrap();
            let endpoint_id = EndpointId::new();
            let slot = Arc::new(CeremonyPreparationSlot::new());
            let _guard = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Register,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();
            _guard.disarm();

            let scope = CeremonyScope::new();
            let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                profile_id,
                endpoint_id,
                mode: PromptMode::Isolated,
                policy_runtime: runtime.clone(),
                audit_gate: audit,
                ceremony_scope: scope,
                require_uv: false,
                prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                preparation_slot: slot.clone(),
            });

            let get_info_response = vec![0x00, 0xa0];
            let (fake, calls) = FakeHandler::new(get_info_response.clone());
            let mut handler = AgentCeremonyHandler::new(fake, ctx);

            assert!(slot.is_active());
            let result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &[0x04, 0xa0])
                .unwrap();
            assert_eq!(result, get_info_response);
            assert_eq!(calls.lock().unwrap().len(), 1);
            assert!(slot.is_active());
        }

        #[test]
        fn test_second_assertion_denied_after_first_clears() {
            let (runtime, audit) = make_runtime();
            let generation = runtime.current_generation();
            let profile_id = ProfileId::new("test").unwrap();
            let endpoint_id = EndpointId::new();
            let slot = Arc::new(CeremonyPreparationSlot::new());
            let _guard = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Authenticate,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();
            _guard.disarm();

            let scope = CeremonyScope::new();
            let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                profile_id,
                endpoint_id,
                mode: PromptMode::Isolated,
                policy_runtime: runtime.clone(),
                audit_gate: audit,
                ceremony_scope: scope,
                require_uv: false,
                prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                preparation_slot: slot.clone(),
            });

            let mut auth_data = vec![0u8; 37];
            auth_data[32] = FLAG_UP | FLAG_UV;
            let mut cred_desc = std::collections::BTreeMap::new();
            cred_desc.insert(Value::Text("id".to_string()), Value::Bytes(vec![0xcc; 32]));
            cred_desc.insert(
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            );
            let mut resp_map = std::collections::BTreeMap::new();
            resp_map.insert(
                Value::Integer(0x01),
                Value::Map(cred_desc.into_iter().collect()),
            );
            resp_map.insert(Value::Integer(0x02), Value::Bytes(auth_data));
            resp_map.insert(Value::Integer(0x03), Value::Bytes(vec![0xdd; 64]));
            let mut ga_response = vec![0x00];
            ga_response.extend(cbor::to_vec(&Value::Map(resp_map.into_iter().collect())).unwrap());

            let (fake, calls) = FakeHandler::new(ga_response);
            let mut handler = AgentCeremonyHandler::new(fake, ctx);

            assert!(slot.is_active());

            let mut ga_map = std::collections::BTreeMap::new();
            ga_map.insert(Value::Integer(0x01), Value::Text("example.com".to_string()));
            ga_map.insert(Value::Integer(0x02), Value::Bytes(vec![0xbb; 32]));
            let cbor_data = cbor::to_vec(&Value::Map(ga_map.into_iter().collect())).unwrap();
            let mut ga_request = vec![0x02];
            ga_request.extend(cbor_data);

            let first_result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &ga_request)
                .unwrap();
            assert_eq!(first_result, vec![CTAP_ERR_OPERATION_DENIED]);
            assert!(!slot.is_active());

            let second_result = handler
                .handle_command(soft_fido2_transport::Cmd::Cbor, &ga_request)
                .unwrap();
            assert_eq!(second_result, vec![CTAP_ERR_OPERATION_DENIED]);
            assert!(calls.lock().unwrap().is_empty());
        }

        #[test]
        fn test_clear_all_removes_preparation() {
            let slot = Arc::new(CeremonyPreparationSlot::new());
            let (runtime, _audit) = make_runtime();
            let generation = runtime.current_generation();

            let _guard = slot
                .install(CeremonyPreparationInput {
                    session_id: PrincipalSessionId::new(),
                    process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                    policy_generation: generation.generation_id.clone(),
                    policy_digest: generation.digest.clone(),
                    credential_ref: None,
                    untrusted_metadata: BoundedUntrustedMetadata::new(
                        "example.com".to_string(),
                        IntentAction::Register,
                        false,
                    ),
                    clamped_grant_ttl_secs: 300,
                    clamped_session_ttl_secs: 3600,
                    trusted_credential_label: None,
                })
                .unwrap();
            _guard.disarm();

            assert!(slot.is_active());
            slot.clear_all();
            assert!(!slot.is_active());
        }

        #[test]
        fn test_guard_drop_clears_preparation() {
            let slot = Arc::new(CeremonyPreparationSlot::new());
            let (runtime, _audit) = make_runtime();
            let generation = runtime.current_generation();

            {
                let _guard = slot
                    .install(CeremonyPreparationInput {
                        session_id: PrincipalSessionId::new(),
                        process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: None,
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            "example.com".to_string(),
                            IntentAction::Register,
                            false,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                assert!(slot.is_active());
            }

            assert!(!slot.is_active());
        }

        mod audit_fault_tests {
            use super::*;
            use crate::agent::audit::{AuditGate, FailAt, FaultPoint};
            use crate::agent::browser::Clock;
            use crate::agent::intent::{MonotonicClock, MonotonicTime, ProcessIdentityDigest};
            use crate::agent::policy_engine::PolicyRuntime;
            use crate::agent::storage::CeremonyScope;
            use passless_core::agent::{
                AgentAuthorization, AgentCeremonyPolicy, AgentConfig, AgentMode,
                AgentProfileConfig, AgentRpRule, AgentStorageConfig, DeviceIdentity, EndpointId,
                PrincipalSessionId, ProfileId, UserPresenceSource, UserVerificationSource,
            };
            use std::collections::BTreeMap;
            use std::path::PathBuf;
            use std::sync::{Arc, Mutex};
            use std::time::{Duration, Instant};

            fn make_faulty_audit(dir: &str, fail_on: FaultPoint) -> Arc<AuditGate> {
                let suffix = format!(
                    "{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                let audit_dir = format!("{}-{}", dir, suffix);
                let _ = std::fs::remove_dir_all(&audit_dir);
                let _ = std::fs::create_dir_all(&audit_dir);
                let _ = std::fs::set_permissions(
                    &audit_dir,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
                let gate = AuditGate::open_with_faults(
                    &audit_dir,
                    64 * 1024 * 1024,
                    Box::new(FailAt(fail_on)),
                )
                .unwrap();
                Arc::new(gate)
            }

            struct CountingHandler {
                calls: Arc<Mutex<usize>>,
                response: Vec<u8>,
            }

            impl CountingHandler {
                fn new(response: Vec<u8>) -> (Self, Arc<Mutex<usize>>) {
                    let calls = Arc::new(Mutex::new(0));
                    (
                        Self {
                            calls: calls.clone(),
                            response,
                        },
                        calls,
                    )
                }
            }

            impl soft_fido2_transport::CommandHandler for CountingHandler {
                fn handle_command(
                    &mut self,
                    _cmd: soft_fido2_transport::Cmd,
                    _data: &[u8],
                ) -> soft_fido2_transport::Result<Vec<u8>> {
                    *self.calls.lock().unwrap() += 1;
                    Ok(self.response.clone())
                }
            }

            struct MockClock {
                inner: Mutex<MockInner>,
            }

            struct MockInner {
                base: Instant,
                offset: Duration,
            }

            impl MockClock {
                fn new() -> Self {
                    Self {
                        inner: Mutex::new(MockInner {
                            base: Instant::now(),
                            offset: Duration::ZERO,
                        }),
                    }
                }
            }

            impl Clock for MockClock {
                fn now(&self) -> Instant {
                    let inner = self.inner.lock().unwrap();
                    inner.base + inner.offset
                }

                fn monotonic_secs(&self) -> u64 {
                    self.inner.lock().unwrap().offset.as_secs()
                }
            }

            impl MonotonicClock for MockClock {
                fn now(&self) -> MonotonicTime {
                    MonotonicTime::from_millis(self.inner.lock().unwrap().offset.as_millis() as u64)
                }
            }

            fn test_device() -> DeviceIdentity {
                DeviceIdentity {
                    name: "test-agent".to_string(),
                    phys: "test-phys".to_string(),
                    uniq: "test-uniq".to_string(),
                    vendor_id: 0x1234,
                    product_id: 0x5678,
                }
            }

            fn make_isolated_config() -> AgentConfig {
                let mut profiles = BTreeMap::new();
                profiles.insert(
                    "test".to_string(),
                    AgentProfileConfig {
                        max_operations: 64,
                        credential_selection:
                            passless_core::agent::config::CredentialSelection::Single,
                        human_verification_prompt:
                            passless_core::agent::config::HumanVerificationPrompt::Always,
                        mode: AgentMode::Isolated,
                        principal_user: "test-user".to_string(),
                        rp_ids: vec!["example.com".to_string()],
                        require_uv: false,
                        credential_refs: None,
                        max_grant_ttl: None,
                        max_session_ttl: None,
                        storage: Some(AgentStorageConfig::Local {
                            path: PathBuf::from("/tmp/test-audit-fault/creds"),
                            pin_path: PathBuf::from("/tmp/test-audit-fault/pin"),
                        }),
                        registration_allowed: true,
                        rules: vec![],
                        device: test_device(),
                        start_url: None,
                        browser_command: None,
                        browser_user: None,
                        browser_runtime_root: None,
                        browser_cdp_expose: None,
                        browser_cdp_port: None,
                    },
                );
                AgentConfig {
                    enabled: true,
                    profiles,
                    audit_path: Some(PathBuf::from("/tmp/test-audit-fault-audit")),
                }
            }

            fn make_allow_config() -> AgentConfig {
                let mut config = make_isolated_config();
                let profile = config.profiles.get_mut("test").unwrap();
                profile.rp_ids.clear();
                profile.registration_allowed = false;
                profile.rules = vec![AgentRpRule {
                    rp_id: "example.com".to_string(),
                    register: AgentCeremonyPolicy {
                        authorization: AgentAuthorization::Allow,
                        user_presence: UserPresenceSource::Agent,
                        user_verification: UserVerificationSource::Agent,
                    },
                    authenticate: AgentCeremonyPolicy::deny(),
                }];
                config
            }

            fn make_runtime_with_faulty_audit(
                audit: Arc<AuditGate>,
            ) -> (Arc<PolicyRuntime>, Arc<AuditGate>) {
                let clock = Arc::new(MockClock::new());
                let config = make_isolated_config();
                let runtime =
                    Arc::new(PolicyRuntime::new(&config, clock.clone(), clock.clone()).unwrap());
                (runtime, audit)
            }

            fn make_mc_request(rp_id: &str) -> Vec<u8> {
                let mut map = std::collections::BTreeMap::new();
                map.insert(Value::Integer(0x01), Value::Bytes(vec![0xaa; 32]));
                let mut rp_map = std::collections::BTreeMap::new();
                rp_map.insert(
                    Value::Text("id".to_string()),
                    Value::Text(rp_id.to_string()),
                );
                map.insert(
                    Value::Integer(0x02),
                    Value::Map(rp_map.into_iter().collect()),
                );
                map.insert(
                    Value::Integer(0x04),
                    Value::Array(vec![{
                        let mut m = std::collections::BTreeMap::new();
                        m.insert(
                            Value::Text("type".to_string()),
                            Value::Text("public-key".to_string()),
                        );
                        m.insert(Value::Text("alg".to_string()), Value::Integer(-7));
                        Value::Map(m.into_iter().collect())
                    }]),
                );
                let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
                let mut raw = vec![0x01];
                raw.extend(cbor_data);
                raw
            }

            fn make_mc_response_bytes() -> Vec<u8> {
                let mut auth_data = vec![0u8; 37];
                auth_data[32] = FLAG_UP | FLAG_UV;

                let mut map = std::collections::BTreeMap::new();
                map.insert(Value::Integer(0x01), Value::Text("none".to_string()));
                map.insert(Value::Integer(0x02), Value::Bytes(auth_data));
                map.insert(
                    Value::Integer(0x03),
                    Value::Map(vec![].into_iter().collect()),
                );
                let mut raw = vec![0x00];
                raw.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());
                raw
            }

            #[test]
            fn test_policy_allow_audit_failure_prevents_inner_dispatch() {
                let audit = make_faulty_audit("/tmp/test-audit-fault", FaultPoint::WriteRecord);
                let (runtime, audit) = make_runtime_with_faulty_audit(audit);
                let generation = runtime.current_generation();
                let profile_id = ProfileId::new("test").unwrap();
                let endpoint_id = EndpointId::new();
                let slot = Arc::new(CeremonyPreparationSlot::new());
                let _guard = slot
                    .install(CeremonyPreparationInput {
                        session_id: PrincipalSessionId::new(),
                        process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: None,
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            "example.com".to_string(),
                            IntentAction::Register,
                            false,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                _guard.disarm();
                let scope = CeremonyScope::new();
                let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                    profile_id,
                    endpoint_id,
                    mode: PromptMode::Isolated,
                    policy_runtime: runtime.clone(),
                    audit_gate: audit,
                    ceremony_scope: scope,
                    require_uv: false,
                    prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                    preparation_slot: slot,
                });

                let (handler, calls) = CountingHandler::new(make_mc_response_bytes());
                let mut handler = AgentCeremonyHandler::new(handler, ctx);

                let request = make_mc_request("example.com");
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                    .unwrap();

                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert_eq!(*calls.lock().unwrap(), 0);
            }

            #[test]
            fn test_ceremony_start_audit_failure_prevents_inner_dispatch() {
                let audit = make_faulty_audit("/tmp/test-audit-fault", FaultPoint::FsyncRecord);
                let (runtime, audit) = make_runtime_with_faulty_audit(audit);
                let generation = runtime.current_generation();
                let profile_id = ProfileId::new("test").unwrap();
                let endpoint_id = EndpointId::new();
                let slot = Arc::new(CeremonyPreparationSlot::new());
                let _guard = slot
                    .install(CeremonyPreparationInput {
                        session_id: PrincipalSessionId::new(),
                        process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: None,
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            "example.com".to_string(),
                            IntentAction::Register,
                            false,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                _guard.disarm();
                let scope = CeremonyScope::new();
                let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                    profile_id,
                    endpoint_id,
                    mode: PromptMode::Isolated,
                    policy_runtime: runtime.clone(),
                    audit_gate: audit,
                    ceremony_scope: scope,
                    require_uv: false,
                    prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                    preparation_slot: slot,
                });

                let (handler, calls) = CountingHandler::new(make_mc_response_bytes());
                let mut handler = AgentCeremonyHandler::new(handler, ctx);

                let request = make_mc_request("example.com");
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                    .unwrap();

                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert_eq!(*calls.lock().unwrap(), 0);
            }

            #[test]
            fn test_ceremony_success_audit_failure_suppresses_success_response() {
                let audit = make_faulty_audit("/tmp/test-audit-fault", FaultPoint::WriteRecord);
                let (runtime, audit) = make_runtime_with_faulty_audit(audit);
                let generation = runtime.current_generation();
                let profile_id = ProfileId::new("test").unwrap();
                let endpoint_id = EndpointId::new();
                let slot = Arc::new(CeremonyPreparationSlot::new());
                let _guard = slot
                    .install(CeremonyPreparationInput {
                        session_id: PrincipalSessionId::new(),
                        process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: None,
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            "example.com".to_string(),
                            IntentAction::Register,
                            false,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                _guard.disarm();
                let scope = CeremonyScope::new();
                let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                    profile_id,
                    endpoint_id,
                    mode: PromptMode::Isolated,
                    policy_runtime: runtime.clone(),
                    audit_gate: audit,
                    ceremony_scope: scope,
                    require_uv: false,
                    prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                    preparation_slot: slot,
                });

                let (handler, calls) = CountingHandler::new(make_mc_response_bytes());
                let mut handler = AgentCeremonyHandler::new(handler, ctx);

                let request = make_mc_request("example.com");
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                    .unwrap();

                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert_eq!(*calls.lock().unwrap(), 0);
            }

            #[test]
            fn test_transport_trait_through_ctap_hid_handler() {
                use soft_fido2_transport::{CtapHidHandler, Message};

                let audit_dir = format!(
                    "/tmp/test-ctap-hid-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                let _ = std::fs::remove_dir_all(&audit_dir);
                let _ = std::fs::create_dir_all(&audit_dir);
                let _ = std::fs::set_permissions(
                    &audit_dir,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
                let audit = Arc::new(AuditGate::open(&audit_dir).unwrap());

                let clock = Arc::new(MockClock::new());
                let config = make_isolated_config();
                let runtime =
                    Arc::new(PolicyRuntime::new(&config, clock.clone(), clock.clone()).unwrap());
                let generation = runtime.current_generation();
                let profile_id = ProfileId::new("test").unwrap();
                let endpoint_id = EndpointId::new();
                let slot = Arc::new(CeremonyPreparationSlot::new());
                let _guard = slot
                    .install(CeremonyPreparationInput {
                        session_id: PrincipalSessionId::new(),
                        process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: None,
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            "example.com".to_string(),
                            IntentAction::Register,
                            false,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                _guard.disarm();
                let scope = CeremonyScope::new();
                let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                    profile_id,
                    endpoint_id,
                    mode: PromptMode::Isolated,
                    policy_runtime: runtime.clone(),
                    audit_gate: audit,
                    ceremony_scope: scope,
                    require_uv: false,
                    prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                    preparation_slot: slot,
                });

                let (inner, calls) = CountingHandler::new(make_mc_response_bytes());
                let ceremony_handler = AgentCeremonyHandler::new(inner, ctx);
                let mut ctap_handler = CtapHidHandler::new(ceremony_handler);

                let request = make_mc_request("example.com");
                let message =
                    Message::new(0x12345678, soft_fido2_transport::Cmd::Cbor, request, None);
                let packets = message.to_packets().unwrap();

                let mut all_response_packets = Vec::new();
                for packet in &packets {
                    let response_packets = ctap_handler.process_packet(packet.clone()).unwrap();
                    all_response_packets.extend(response_packets);
                }

                assert!(!all_response_packets.is_empty());

                let response = Message::from_packets(&all_response_packets, None).unwrap();
                assert_eq!(response.cmd, soft_fido2_transport::Cmd::Cbor);
                assert_eq!(response.data, vec![CTAP_ERR_OPERATION_DENIED]);
                assert_eq!(*calls.lock().unwrap(), 0);
            }

            #[test]
            fn test_prompt_deny_returns_denied_without_dispatching() {
                use crate::agent::prompt::{MockPromptHandle, PromptDecision};

                let audit_dir = format!(
                    "/tmp/test-prompt-deny-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                let _ = std::fs::remove_dir_all(&audit_dir);
                let _ = std::fs::create_dir_all(&audit_dir);
                let _ = std::fs::set_permissions(
                    &audit_dir,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
                let audit = Arc::new(AuditGate::open(&audit_dir).unwrap());
                let config = make_isolated_config();
                let clock = Arc::new(MockClock::new());
                let runtime =
                    Arc::new(PolicyRuntime::new(&config, clock.clone(), clock.clone()).unwrap());
                let generation = runtime.current_generation();
                let profile_id = ProfileId::new("test").unwrap();
                let session_id = PrincipalSessionId::new();
                let endpoint_id = EndpointId::new();
                let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");

                let _pending_id = runtime
                    .principal_create_pending_intent(crate::agent::intent::CreateIntentParams {
                        profile_id: profile_id.clone(),
                        session_id: session_id.clone(),
                        endpoint_id: endpoint_id.clone(),
                        process_digest: process_digest.clone(),
                        action: passless_core::agent::protocol::IntentAction::Register,
                        rp_id: "example.com".to_string(),
                        credential_ref: None,
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        require_uv: false,
                        ttl_ms: Some(60_000),
                    })
                    .unwrap();

                let slot = Arc::new(CeremonyPreparationSlot::new());
                let _guard = slot
                    .install(CeremonyPreparationInput {
                        session_id: session_id.clone(),
                        process_digest: process_digest.clone(),
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: None,
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            "example.com".to_string(),
                            IntentAction::Register,
                            false,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                _guard.disarm();
                let scope = CeremonyScope::new();
                let mock_prompt = Arc::new(MockPromptHandle::new(PromptDecision::Denied, 10));
                let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                    profile_id: profile_id.clone(),
                    endpoint_id: endpoint_id.clone(),
                    mode: PromptMode::Isolated,
                    policy_runtime: runtime.clone(),
                    audit_gate: audit,
                    ceremony_scope: scope,
                    require_uv: false,
                    prompt_handle: mock_prompt,
                    preparation_slot: slot,
                });

                let (handler, calls) = CountingHandler::new(make_mc_response_bytes());
                let mut handler = AgentCeremonyHandler::new(handler, ctx);

                let request = make_mc_request("example.com");
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                    .unwrap();

                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert_eq!(*calls.lock().unwrap(), 0);

                let _ = std::fs::remove_dir_all(&audit_dir);
            }

            #[test]
            fn test_policy_allow_skips_denied_prompt_and_dispatches() {
                use crate::agent::prompt::{MockPromptHandle, PromptDecision};

                let audit_dir = format!(
                    "/tmp/test-policy-allow-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                std::fs::create_dir_all(&audit_dir).unwrap();
                std::fs::set_permissions(
                    &audit_dir,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                )
                .unwrap();
                let audit = Arc::new(AuditGate::open(&audit_dir).unwrap());
                let config = make_allow_config();
                let clock = Arc::new(MockClock::new());
                let runtime =
                    Arc::new(PolicyRuntime::new(&config, clock.clone(), clock.clone()).unwrap());
                let generation = runtime.current_generation();
                let profile_id = ProfileId::new("test").unwrap();
                let session_id = PrincipalSessionId::new();
                let endpoint_id = EndpointId::new();
                let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");

                runtime
                    .principal_create_pending_intent(crate::agent::intent::CreateIntentParams {
                        profile_id: profile_id.clone(),
                        session_id: session_id.clone(),
                        endpoint_id: endpoint_id.clone(),
                        process_digest: process_digest.clone(),
                        action: IntentAction::Register,
                        rp_id: "example.com".to_string(),
                        credential_ref: None,
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        require_uv: true,
                        ttl_ms: Some(60_000),
                    })
                    .unwrap();

                let slot = Arc::new(CeremonyPreparationSlot::new());
                let guard = slot
                    .install(CeremonyPreparationInput {
                        session_id,
                        process_digest,
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: None,
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            "example.com".to_string(),
                            IntentAction::Register,
                            true,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                guard.disarm();

                let scope = CeremonyScope::new();
                let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                    profile_id,
                    endpoint_id,
                    mode: PromptMode::Isolated,
                    policy_runtime: runtime,
                    audit_gate: audit,
                    ceremony_scope: scope,
                    require_uv: false,
                    prompt_handle: Arc::new(MockPromptHandle::new(PromptDecision::Denied, 0)),
                    preparation_slot: slot,
                });
                let (inner, calls) = CountingHandler::new(make_mc_response_bytes());
                let mut handler = AgentCeremonyHandler::new(inner, ctx);

                let result = handler
                    .handle_command(
                        soft_fido2_transport::Cmd::Cbor,
                        &make_mc_request("example.com"),
                    )
                    .unwrap();

                assert_eq!(result, make_mc_response_bytes());
                assert_eq!(*calls.lock().unwrap(), 1);
                let _ = std::fs::remove_dir_all(&audit_dir);
            }

            #[test]
            fn test_missing_pending_request_fails_closed() {
                let audit_dir = format!(
                    "/tmp/test-no-pending-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                let _ = std::fs::remove_dir_all(&audit_dir);
                let _ = std::fs::create_dir_all(&audit_dir);
                let _ = std::fs::set_permissions(
                    &audit_dir,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
                let audit = Arc::new(AuditGate::open(&audit_dir).unwrap());
                let config = make_isolated_config();
                let clock = Arc::new(MockClock::new());
                let runtime =
                    Arc::new(PolicyRuntime::new(&config, clock.clone(), clock.clone()).unwrap());
                let generation = runtime.current_generation();
                let profile_id = ProfileId::new("test").unwrap();
                let endpoint_id = EndpointId::new();
                let slot = Arc::new(CeremonyPreparationSlot::new());
                let _guard = slot
                    .install(CeremonyPreparationInput {
                        session_id: PrincipalSessionId::new(),
                        process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: None,
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            "example.com".to_string(),
                            IntentAction::Register,
                            false,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                _guard.disarm();
                let scope = CeremonyScope::new();
                let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                    profile_id: profile_id.clone(),
                    endpoint_id: endpoint_id.clone(),
                    mode: PromptMode::Isolated,
                    policy_runtime: runtime.clone(),
                    audit_gate: audit,
                    ceremony_scope: scope,
                    require_uv: false,
                    prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                    preparation_slot: slot,
                });

                let (handler, calls) = CountingHandler::new(make_mc_response_bytes());
                let mut handler = AgentCeremonyHandler::new(handler, ctx);

                let request = make_mc_request("example.com");
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                    .unwrap();

                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert_eq!(*calls.lock().unwrap(), 0);
                let _ = std::fs::remove_dir_all(&audit_dir);
            }
        }

        mod rp_action_mismatch_tests {
            use super::*;
            use crate::agent::browser::Clock;
            use crate::agent::intent::{MonotonicClock, MonotonicTime, ProcessIdentityDigest};
            use crate::agent::policy_engine::PolicyRuntime;
            use crate::agent::prompt::AutoApproveHandle;
            use crate::agent::storage::CeremonyScope;
            use passless_core::agent::{
                AgentConfig, AgentMode, AgentProfileConfig, AgentStorageConfig, CredentialRef,
                DeviceIdentity, EndpointId, PrincipalSessionId, ProfileId,
            };
            use std::collections::BTreeMap;
            use std::path::PathBuf;
            use std::sync::{Arc, Mutex};
            use std::time::{Duration, Instant};

            use passless_core::agent::protocol::IntentAction;

            struct MockClock {
                inner: Mutex<MockInner>,
            }
            struct MockInner {
                base: Instant,
                offset: Duration,
            }
            impl MockClock {
                fn new() -> Self {
                    Self {
                        inner: Mutex::new(MockInner {
                            base: Instant::now(),
                            offset: Duration::ZERO,
                        }),
                    }
                }
            }
            impl Clock for MockClock {
                fn now(&self) -> Instant {
                    let inner = self.inner.lock().unwrap();
                    inner.base + inner.offset
                }
                fn monotonic_secs(&self) -> u64 {
                    self.inner.lock().unwrap().offset.as_secs()
                }
            }
            impl MonotonicClock for MockClock {
                fn now(&self) -> MonotonicTime {
                    MonotonicTime::from_millis(self.inner.lock().unwrap().offset.as_millis() as u64)
                }
            }

            fn test_device() -> DeviceIdentity {
                DeviceIdentity {
                    name: "test-agent".to_string(),
                    phys: "test-phys".to_string(),
                    uniq: "test-uniq".to_string(),
                    vendor_id: 0x1234,
                    product_id: 0x5678,
                }
            }

            fn make_config() -> AgentConfig {
                let mut profiles = BTreeMap::new();
                profiles.insert(
                    "test".to_string(),
                    AgentProfileConfig {
                        max_operations: 64,
                        credential_selection:
                            passless_core::agent::config::CredentialSelection::Single,
                        human_verification_prompt:
                            passless_core::agent::config::HumanVerificationPrompt::Always,
                        mode: AgentMode::Isolated,
                        principal_user: "test-user".to_string(),
                        rp_ids: vec!["example.com".to_string()],
                        require_uv: false,
                        credential_refs: None,
                        max_grant_ttl: None,
                        max_session_ttl: None,
                        storage: Some(AgentStorageConfig::Local {
                            path: PathBuf::from("/tmp/test-rp-mismatch/creds"),
                            pin_path: PathBuf::from("/tmp/test-rp-mismatch/pin"),
                        }),
                        registration_allowed: true,
                        rules: vec![],
                        device: test_device(),
                        start_url: None,
                        browser_command: None,
                        browser_user: None,
                        browser_runtime_root: None,
                        browser_cdp_expose: None,
                        browser_cdp_port: None,
                    },
                );
                AgentConfig {
                    enabled: true,
                    profiles,
                    audit_path: Some(PathBuf::from("/tmp/test-rp-mismatch-audit")),
                }
            }

            fn make_setup(
                prep_rp: &str,
                prep_action: IntentAction,
            ) -> (
                AgentCeremonyHandler<super::FakeHandler>,
                Arc<CeremonyPreparationSlot>,
            ) {
                let suffix = format!(
                    "{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                let audit_dir = format!("/tmp/test-rp-mismatch-audit-{}", suffix);
                let _ = std::fs::remove_dir_all(&audit_dir);
                let _ = std::fs::create_dir_all(&audit_dir);
                let _ = std::fs::set_permissions(
                    &audit_dir,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
                let audit = Arc::new(crate::agent::audit::AuditGate::open(&audit_dir).unwrap());
                let clock = Arc::new(MockClock::new());
                let config = make_config();
                let runtime =
                    Arc::new(PolicyRuntime::new(&config, clock.clone(), clock.clone()).unwrap());
                let generation = runtime.current_generation();
                let profile_id = ProfileId::new("test").unwrap();
                let endpoint_id = EndpointId::new();
                let slot = Arc::new(CeremonyPreparationSlot::new());
                let _guard = slot
                    .install(CeremonyPreparationInput {
                        session_id: PrincipalSessionId::new(),
                        process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: None,
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            prep_rp.to_string(),
                            prep_action,
                            false,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                _guard.disarm();
                let scope = CeremonyScope::new();
                let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                    profile_id,
                    endpoint_id,
                    mode: PromptMode::Isolated,
                    policy_runtime: runtime,
                    audit_gate: audit,
                    ceremony_scope: scope,
                    require_uv: false,
                    prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                    preparation_slot: slot.clone(),
                });
                let mut auth_data = vec![0u8; 37];
                auth_data[32] = FLAG_UP | FLAG_UV;
                let mut map = std::collections::BTreeMap::new();
                map.insert(Value::Integer(0x01), Value::Text("none".to_string()));
                map.insert(Value::Integer(0x02), Value::Bytes(auth_data));
                map.insert(
                    Value::Integer(0x03),
                    Value::Map(vec![].into_iter().collect()),
                );
                let mut resp = vec![0x00];
                resp.extend(cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap());
                let (fake, _) = super::FakeHandler::new(resp);
                let handler = AgentCeremonyHandler::new(fake, ctx);
                (handler, slot)
            }

            fn make_mc_request(rp_id: &str) -> Vec<u8> {
                let mut map = std::collections::BTreeMap::new();
                map.insert(Value::Integer(0x01), Value::Bytes(vec![0xaa; 32]));
                let mut rp_map = std::collections::BTreeMap::new();
                rp_map.insert(
                    Value::Text("id".to_string()),
                    Value::Text(rp_id.to_string()),
                );
                map.insert(
                    Value::Integer(0x02),
                    Value::Map(rp_map.into_iter().collect()),
                );
                map.insert(
                    Value::Integer(0x04),
                    Value::Array(vec![{
                        let mut m = std::collections::BTreeMap::new();
                        m.insert(
                            Value::Text("type".to_string()),
                            Value::Text("public-key".to_string()),
                        );
                        m.insert(Value::Text("alg".to_string()), Value::Integer(-7));
                        Value::Map(m.into_iter().collect())
                    }]),
                );
                let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
                let mut raw = vec![0x01];
                raw.extend(cbor_data);
                raw
            }

            fn make_ga_request(rp_id: &str) -> Vec<u8> {
                let mut map = std::collections::BTreeMap::new();
                map.insert(Value::Integer(0x01), Value::Text(rp_id.to_string()));
                map.insert(Value::Integer(0x02), Value::Bytes(vec![0xbb; 32]));
                let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
                let mut raw = vec![0x02];
                raw.extend(cbor_data);
                raw
            }

            #[test]
            fn test_register_prep_with_get_assertion_cmd_denied() {
                let (mut handler, slot) = make_setup("example.com", IntentAction::Register);
                assert!(slot.is_active());
                let request = make_ga_request("example.com");
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                    .unwrap();
                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert!(!slot.is_active());
            }

            #[test]
            fn test_authenticate_prep_with_make_credential_cmd_denied() {
                let (mut handler, slot) = make_setup("example.com", IntentAction::Authenticate);
                assert!(slot.is_active());
                let request = make_mc_request("example.com");
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                    .unwrap();
                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert!(!slot.is_active());
            }

            #[test]
            fn test_rp_mismatch_clears_prep() {
                let (mut handler, slot) = make_setup("example.com", IntentAction::Register);
                assert!(slot.is_active());
                let request = make_mc_request("evil.com");
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                    .unwrap();
                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert!(!slot.is_active());
            }

            #[test]
            fn test_rp_exact_match_case_insensitive() {
                let (mut handler, slot) = make_setup("example.com", IntentAction::Register);
                assert!(slot.is_active());
                let request = make_mc_request("EXAMPLE.COM");
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                    .unwrap();
                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert!(!slot.is_active());
            }

            #[test]
            fn test_auth_prep_with_cred_zero_allow_refs_denied() {
                let suffix = format!(
                    "{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                let audit_dir = format!("/tmp/test-auth-cred-mismatch-{}", suffix);
                let _ = std::fs::remove_dir_all(&audit_dir);
                let _ = std::fs::create_dir_all(&audit_dir);
                let _ = std::fs::set_permissions(
                    &audit_dir,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
                let audit = Arc::new(crate::agent::audit::AuditGate::open(&audit_dir).unwrap());
                let clock = Arc::new(MockClock::new());
                let config = make_config();
                let runtime =
                    Arc::new(PolicyRuntime::new(&config, clock.clone(), clock.clone()).unwrap());
                let generation = runtime.current_generation();
                let profile_id = ProfileId::new("test").unwrap();
                let endpoint_id = EndpointId::new();
                let slot = Arc::new(CeremonyPreparationSlot::new());
                let expected_cred = CredentialRef::with_default_domain(b"expected-cred");
                let _guard = slot
                    .install(CeremonyPreparationInput {
                        session_id: PrincipalSessionId::new(),
                        process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: Some(expected_cred),
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            "example.com".to_string(),
                            IntentAction::Authenticate,
                            false,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                _guard.disarm();
                let scope = CeremonyScope::new();
                let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                    profile_id,
                    endpoint_id,
                    mode: PromptMode::Isolated,
                    policy_runtime: runtime,
                    audit_gate: audit,
                    ceremony_scope: scope,
                    require_uv: false,
                    prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                    preparation_slot: slot.clone(),
                });
                let (fake, _) = super::FakeHandler::new(vec![CTAP_ERR_OPERATION_DENIED]);
                let mut handler = AgentCeremonyHandler::new(fake, ctx);

                assert!(slot.is_active());
                let request = make_ga_request("example.com");
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &request)
                    .unwrap();
                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert!(!slot.is_active());
            }

            #[test]
            fn test_auth_prep_with_cred_multiple_allow_refs_denied() {
                let suffix = format!(
                    "{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                let audit_dir = format!("/tmp/test-auth-multi-allow-{}", suffix);
                let _ = std::fs::remove_dir_all(&audit_dir);
                let _ = std::fs::create_dir_all(&audit_dir);
                let _ = std::fs::set_permissions(
                    &audit_dir,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
                let audit = Arc::new(crate::agent::audit::AuditGate::open(&audit_dir).unwrap());
                let clock = Arc::new(MockClock::new());
                let config = make_config();
                let runtime =
                    Arc::new(PolicyRuntime::new(&config, clock.clone(), clock.clone()).unwrap());
                let generation = runtime.current_generation();
                let profile_id = ProfileId::new("test").unwrap();
                let endpoint_id = EndpointId::new();
                let slot = Arc::new(CeremonyPreparationSlot::new());
                let expected_cred = CredentialRef::with_default_domain(b"expected-cred");
                let _guard = slot
                    .install(CeremonyPreparationInput {
                        session_id: PrincipalSessionId::new(),
                        process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                        policy_generation: generation.generation_id.clone(),
                        policy_digest: generation.digest.clone(),
                        credential_ref: Some(expected_cred.clone()),
                        untrusted_metadata: BoundedUntrustedMetadata::new(
                            "example.com".to_string(),
                            IntentAction::Authenticate,
                            false,
                        ),
                        clamped_grant_ttl_secs: 300,
                        clamped_session_ttl_secs: 3600,
                        trusted_credential_label: None,
                    })
                    .unwrap();
                _guard.disarm();
                let scope = CeremonyScope::new();
                let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                    profile_id,
                    endpoint_id,
                    mode: PromptMode::Isolated,
                    policy_runtime: runtime,
                    audit_gate: audit,
                    ceremony_scope: scope,
                    require_uv: false,
                    prompt_handle: Arc::new(AutoApproveHandle::new(0)),
                    preparation_slot: slot.clone(),
                });
                let (fake, _) = super::FakeHandler::new(vec![CTAP_ERR_OPERATION_DENIED]);
                let mut handler = AgentCeremonyHandler::new(fake, ctx);

                let mut map = std::collections::BTreeMap::new();
                map.insert(Value::Integer(0x01), Value::Text("example.com".to_string()));
                map.insert(Value::Integer(0x02), Value::Bytes(vec![0xbb; 32]));
                let mut desc1 = std::collections::BTreeMap::new();
                desc1.insert(Value::Text("id".to_string()), Value::Bytes(vec![0xcc; 32]));
                desc1.insert(
                    Value::Text("type".to_string()),
                    Value::Text("public-key".to_string()),
                );
                let mut desc2 = std::collections::BTreeMap::new();
                desc2.insert(Value::Text("id".to_string()), Value::Bytes(vec![0xdd; 32]));
                desc2.insert(
                    Value::Text("type".to_string()),
                    Value::Text("public-key".to_string()),
                );
                map.insert(
                    Value::Integer(0x03),
                    Value::Array(vec![
                        Value::Map(desc1.into_iter().collect()),
                        Value::Map(desc2.into_iter().collect()),
                    ]),
                );
                let cbor_data = cbor::to_vec(&Value::Map(map.into_iter().collect())).unwrap();
                let mut raw = vec![0x02];
                raw.extend(cbor_data);

                assert!(slot.is_active());
                let result = handler
                    .handle_command(soft_fido2_transport::Cmd::Cbor, &raw)
                    .unwrap();
                assert_eq!(result, vec![CTAP_ERR_OPERATION_DENIED]);
                assert!(!slot.is_active());
            }
        }
    }
}
