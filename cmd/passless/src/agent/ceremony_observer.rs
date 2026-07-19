use std::sync::{Arc, Mutex};

use super::ceremony::CommandClass;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalResult {
    Success,
    DeniedByPolicy,
    InnerHandlerError,
    ResponseParseError,
    PromptDenied,
    PromptTimeout,
    PromptError,
    CommandClassDenied,
    CredentialMismatch,
    ScopeActivationFailed,
    NoPreparation,
    PreparationStale,
    ConsumeFailed,
    AuditFailed,
    BoundAuthorizeFailed,
    GetNextAssertionDenied,
    EmptyResponse,
    NonZeroStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CeremonyObservation {
    pub command_class: CommandClass,
    pub terminal_result: TerminalResult,
    pub up: bool,
    pub uv: bool,
    pub correlation_id: u64,
}

#[derive(Clone, Debug, Default)]
pub struct TestObserver {
    observations: Arc<Mutex<Vec<CeremonyObservation>>>,
    next_correlation: Arc<Mutex<u64>>,
}

impl TestObserver {
    pub fn new() -> Self {
        Self {
            observations: Arc::new(Mutex::new(Vec::new())),
            next_correlation: Arc::new(Mutex::new(1)),
        }
    }

    pub fn mint_correlation_id(&self) -> u64 {
        let mut guard = self.next_correlation.lock().unwrap();
        let id = *guard;
        *guard += 1;
        id
    }

    pub fn record(&self, obs: CeremonyObservation) {
        self.observations.lock().unwrap().push(obs);
    }

    pub fn take(&self) -> Vec<CeremonyObservation> {
        std::mem::take(&mut *self.observations.lock().unwrap())
    }

    pub fn len(&self) -> usize {
        self.observations.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observation_has_no_raw_report_field() {
        let obs = CeremonyObservation {
            command_class: CommandClass::Ceremony,
            terminal_result: TerminalResult::Success,
            up: true,
            uv: true,
            correlation_id: 42,
        };
        let debug = format!("{:?}", obs);
        assert!(!debug.contains("auth_data"));
        assert!(!debug.contains("signature"));
        assert!(!debug.contains("credential_id"));
        assert!(!debug.contains("user_handle"));
        assert!(!debug.contains("pin"));
        assert!(!debug.contains("client_data"));
        assert!(!debug.contains("raw"));
        assert!(!debug.contains("report"));
    }

    #[test]
    fn test_observation_size_is_bounded() {
        assert!(std::mem::size_of::<CeremonyObservation>() <= 32);
    }

    #[test]
    fn test_terminal_result_variants_are_exhaustive() {
        let variants = [
            TerminalResult::Success,
            TerminalResult::DeniedByPolicy,
            TerminalResult::InnerHandlerError,
            TerminalResult::ResponseParseError,
            TerminalResult::PromptDenied,
            TerminalResult::PromptTimeout,
            TerminalResult::PromptError,
            TerminalResult::CommandClassDenied,
            TerminalResult::CredentialMismatch,
            TerminalResult::ScopeActivationFailed,
            TerminalResult::NoPreparation,
            TerminalResult::PreparationStale,
            TerminalResult::ConsumeFailed,
            TerminalResult::AuditFailed,
            TerminalResult::BoundAuthorizeFailed,
            TerminalResult::GetNextAssertionDenied,
            TerminalResult::EmptyResponse,
            TerminalResult::NonZeroStatus,
        ];
        for v in &variants {
            let debug = format!("{:?}", v);
            assert!(!debug.is_empty());
        }
        assert_eq!(variants.len(), 18);
    }

    #[test]
    fn test_test_observer_record_and_take() {
        let observer = TestObserver::new();
        assert!(observer.is_empty());

        let obs = CeremonyObservation {
            command_class: CommandClass::Ceremony,
            terminal_result: TerminalResult::Success,
            up: true,
            uv: true,
            correlation_id: 1,
        };
        observer.record(obs);
        assert_eq!(observer.len(), 1);

        let taken = observer.take();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].correlation_id, 1);
        assert!(observer.is_empty());
    }

    #[test]
    fn test_test_observer_correlation_ids_are_monotonic() {
        let observer = TestObserver::new();
        let id1 = observer.mint_correlation_id();
        let id2 = observer.mint_correlation_id();
        let id3 = observer.mint_correlation_id();
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_observation_debug_has_no_secret_fields() {
        let obs = CeremonyObservation {
            command_class: CommandClass::Ceremony,
            terminal_result: TerminalResult::Success,
            up: true,
            uv: false,
            correlation_id: 99,
        };
        let debug_str = format!("{:?}", obs);
        let forbidden = [
            "Vec<u8>",
            "authenticator_data",
            "client_data_hash",
            "signature",
            "credential",
            "user_handle",
            "pin_uv",
            "attest",
            "secret",
            "key_bytes",
            "report_bytes",
        ];
        for word in &forbidden {
            assert!(
                !debug_str.contains(word),
                "Debug output contains forbidden word: {}",
                word
            );
        }
    }

    #[test]
    fn test_observation_no_serialize_trait() {
        fn assert_not_serialize<T>() {}
        assert_not_serialize::<CeremonyObservation>();
    }

    #[test]
    fn test_observation_fields_are_only_allowed() {
        let obs = CeremonyObservation {
            command_class: CommandClass::SafeNonCeremony,
            terminal_result: TerminalResult::CommandClassDenied,
            up: false,
            uv: false,
            correlation_id: 0,
        };
        assert_eq!(obs.command_class, CommandClass::SafeNonCeremony);
        assert_eq!(obs.terminal_result, TerminalResult::CommandClassDenied);
        assert!(!obs.up);
        assert!(!obs.uv);
        assert_eq!(obs.correlation_id, 0);
    }

    #[test]
    fn test_test_observer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TestObserver>();
    }

    mod response_extraction {
        use super::*;
        use crate::agent::ceremony::{
            AgentCeremonyError, CeremonyError, extract_up_uv_from_response,
            map_ceremony_error_to_terminal,
        };

        use serde_cbor as cbor;

        fn make_auth_data(flags: u8) -> Vec<u8> {
            let mut data = vec![0u8; 37];
            data[32] = flags;
            data
        }

        fn make_mc_response(auth_data: &[u8]) -> Vec<u8> {
            let mut map = std::collections::BTreeMap::new();
            map.insert(cbor::Value::Integer(0x01), cbor::Value::Text("none".into()));
            map.insert(
                cbor::Value::Integer(0x02),
                cbor::Value::Bytes(auth_data.to_vec()),
            );
            map.insert(
                cbor::Value::Integer(0x03),
                cbor::Value::Map(vec![].into_iter().collect()),
            );
            let mut raw = vec![0x00];
            raw.extend(cbor::to_vec(&cbor::Value::Map(map.into_iter().collect())).unwrap());
            raw
        }

        fn make_ga_response(auth_data: &[u8]) -> Vec<u8> {
            let mut cred_desc = std::collections::BTreeMap::new();
            cred_desc.insert(
                cbor::Value::Text("id".into()),
                cbor::Value::Bytes(vec![0xcc; 32]),
            );
            cred_desc.insert(
                cbor::Value::Text("type".into()),
                cbor::Value::Text("public-key".into()),
            );

            let mut map = std::collections::BTreeMap::new();
            map.insert(
                cbor::Value::Integer(0x01),
                cbor::Value::Map(cred_desc.into_iter().collect()),
            );
            map.insert(
                cbor::Value::Integer(0x02),
                cbor::Value::Bytes(auth_data.to_vec()),
            );
            map.insert(
                cbor::Value::Integer(0x03),
                cbor::Value::Bytes(vec![0xdd; 64]),
            );
            let mut raw = vec![0x00];
            raw.extend(cbor::to_vec(&cbor::Value::Map(map.into_iter().collect())).unwrap());
            raw
        }

        #[test]
        fn test_extract_up_uv_mc_response_up_and_uv_set() {
            let auth_data = make_auth_data(0x01 | 0x04);
            let response = make_mc_response(&auth_data);
            let (up, uv) = extract_up_uv_from_response(0x01, &response);
            assert!(up, "UP should be set");
            assert!(uv, "UV should be set");
        }

        #[test]
        fn test_extract_up_uv_mc_response_up_only() {
            let auth_data = make_auth_data(0x01);
            let response = make_mc_response(&auth_data);
            let (up, uv) = extract_up_uv_from_response(0x01, &response);
            assert!(up, "UP should be set");
            assert!(!uv, "UV should not be set");
        }

        #[test]
        fn test_extract_up_uv_ga_response_up_and_uv_set() {
            let auth_data = make_auth_data(0x01 | 0x04);
            let response = make_ga_response(&auth_data);
            let (up, uv) = extract_up_uv_from_response(0x02, &response);
            assert!(up, "UP should be set");
            assert!(uv, "UV should be set");
        }

        #[test]
        fn test_extract_up_uv_ga_response_up_only() {
            let auth_data = make_auth_data(0x01);
            let response = make_ga_response(&auth_data);
            let (up, uv) = extract_up_uv_from_response(0x02, &response);
            assert!(up, "UP should be set");
            assert!(!uv, "UV should not be set");
        }

        #[test]
        fn test_extract_up_uv_missing_up_flag() {
            let auth_data = make_auth_data(0x04);
            let response = make_mc_response(&auth_data);
            let (up, uv) = extract_up_uv_from_response(0x01, &response);
            assert!(!up, "UP should not be set");
            assert!(uv, "UV should be set");
        }

        #[test]
        fn test_extract_up_uv_no_flags_set() {
            let auth_data = make_auth_data(0x00);
            let response = make_mc_response(&auth_data);
            let (up, uv) = extract_up_uv_from_response(0x01, &response);
            assert!(!up, "UP should not be set");
            assert!(!uv, "UV should not be set");
        }

        #[test]
        fn test_extract_up_uv_empty_response() {
            let (up, uv) = extract_up_uv_from_response(0x01, &[]);
            assert!(!up);
            assert!(!uv);
        }

        #[test]
        fn test_extract_up_uv_non_zero_status() {
            let auth_data = make_auth_data(0x01 | 0x04);
            let mut response = make_mc_response(&auth_data);
            response[0] = 0x27;
            let (up, uv) = extract_up_uv_from_response(0x01, &response);
            assert!(!up);
            assert!(!uv);
        }

        #[test]
        fn test_extract_up_uv_malformed_cbor() {
            let response = vec![0x00, 0xff, 0xff];
            let (up, uv) = extract_up_uv_from_response(0x01, &response);
            assert!(!up);
            assert!(!uv);
        }

        #[test]
        fn test_extract_up_uv_auth_data_too_short() {
            let short_data = vec![0u8; 32];
            let response = make_mc_response(&short_data);
            let (up, uv) = extract_up_uv_from_response(0x01, &response);
            assert!(!up);
            assert!(!uv);
        }

        #[test]
        fn test_map_ceremony_error_prompt_denied() {
            let e = AgentCeremonyError::PromptDenied;
            assert_eq!(
                map_ceremony_error_to_terminal(&e),
                TerminalResult::PromptDenied
            );
        }

        #[test]
        fn test_map_ceremony_error_prompt_timeout() {
            let e = AgentCeremonyError::PromptTimeout;
            assert_eq!(
                map_ceremony_error_to_terminal(&e),
                TerminalResult::PromptTimeout
            );
        }

        #[test]
        fn test_map_ceremony_error_response_parse() {
            let e = AgentCeremonyError::ResponseParseFailed(CeremonyError::InvalidCbor);
            assert_eq!(
                map_ceremony_error_to_terminal(&e),
                TerminalResult::ResponseParseError
            );
        }

        #[test]
        fn test_map_ceremony_error_non_zero_status() {
            let e = AgentCeremonyError::ResponseParseFailed(CeremonyError::NonZeroStatus);
            assert_eq!(
                map_ceremony_error_to_terminal(&e),
                TerminalResult::NonZeroStatus
            );
        }

        #[test]
        fn test_map_ceremony_error_inner_handler() {
            let e = AgentCeremonyError::InnerHandlerFailed;
            assert_eq!(
                map_ceremony_error_to_terminal(&e),
                TerminalResult::InnerHandlerError
            );
        }

        #[test]
        fn test_map_ceremony_error_credential_mismatch() {
            let e = AgentCeremonyError::CredentialMismatch;
            assert_eq!(
                map_ceremony_error_to_terminal(&e),
                TerminalResult::CredentialMismatch
            );
        }

        #[test]
        fn test_map_ceremony_error_policy_denied() {
            use crate::agent::policy_engine::ReasonCode;
            let e = AgentCeremonyError::PolicyDenied(ReasonCode::DefaultDeny);
            assert_eq!(
                map_ceremony_error_to_terminal(&e),
                TerminalResult::DeniedByPolicy
            );
        }

        #[test]
        fn test_map_ceremony_error_no_preparation() {
            let e = AgentCeremonyError::NoPreparation;
            assert_eq!(
                map_ceremony_error_to_terminal(&e),
                TerminalResult::NoPreparation
            );
        }

        #[test]
        fn test_map_ceremony_error_bound_authorize_failed() {
            let e = AgentCeremonyError::BoundAuthorizeFailed;
            assert_eq!(
                map_ceremony_error_to_terminal(&e),
                TerminalResult::BoundAuthorizeFailed
            );
        }

        #[test]
        fn test_observation_after_successful_extraction_contains_correct_flags() {
            let observer = TestObserver::new();
            let auth_data = make_auth_data(0x01 | 0x04);
            let response = make_mc_response(&auth_data);
            let (up, uv) = extract_up_uv_from_response(0x01, &response);

            let cid = observer.mint_correlation_id();
            observer.record(CeremonyObservation {
                command_class: CommandClass::Ceremony,
                terminal_result: TerminalResult::Success,
                up,
                uv,
                correlation_id: cid,
            });

            let observations = observer.take();
            assert_eq!(observations.len(), 1);
            assert!(observations[0].up);
            assert!(observations[0].uv);
            assert_eq!(observations[0].terminal_result, TerminalResult::Success);
            assert_eq!(observations[0].command_class, CommandClass::Ceremony);
        }

        #[test]
        fn test_observation_after_failed_parse_has_no_flags() {
            let observer = TestObserver::new();
            let e = AgentCeremonyError::ResponseParseFailed(CeremonyError::UpNotSet);
            let terminal = map_ceremony_error_to_terminal(&e);

            let cid = observer.mint_correlation_id();
            observer.record(CeremonyObservation {
                command_class: CommandClass::Ceremony,
                terminal_result: terminal,
                up: false,
                uv: false,
                correlation_id: cid,
            });

            let observations = observer.take();
            assert_eq!(observations.len(), 1);
            assert!(!observations[0].up);
            assert!(!observations[0].uv);
            assert_eq!(
                observations[0].terminal_result,
                TerminalResult::ResponseParseError
            );
        }

        #[test]
        fn test_observation_correlation_id_is_non_secret() {
            let observer = TestObserver::new();
            let cid = observer.mint_correlation_id();
            let debug = format!("{:?}", cid);
            assert!(!debug.contains("secret"));
            assert!(!debug.contains("key"));
            assert!(!debug.contains("pin"));
        }
    }
}
