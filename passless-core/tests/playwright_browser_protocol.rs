#[cfg(feature = "agent")]
mod tests {
    use passless_core::agent::protocol::{
        BrowserStatusResponse, CURRENT_VERSION, PrincipalRequest, PrincipalResponse, Validate,
    };

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn protocol_minor_version_covers_ensure_browser() {
        assert_eq!(CURRENT_VERSION.major, 1);
        assert!(CURRENT_VERSION.minor >= 2);
    }

    #[test]
    fn ensure_browser_round_trips_without_start_url() {
        let request = PrincipalRequest::EnsureBrowser {
            start_url: None,
            headed: false,
            direct_cdp: false,
        };
        request.validate().unwrap();

        let json = serde_json::to_string(&request).unwrap();
        let decoded: PrincipalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn ensure_browser_headed_is_optional_on_the_wire() {
        let headed = PrincipalRequest::EnsureBrowser {
            start_url: None,
            headed: true,
            direct_cdp: false,
        };
        headed.validate().unwrap();
        let json = serde_json::to_string(&headed).unwrap();
        assert!(json.contains("\"headed\":true"), "{json}");
        assert_eq!(
            serde_json::from_str::<PrincipalRequest>(&json).unwrap(),
            headed
        );

        // A request without the field (an older client) is headless, and headless is not sent.
        let old: PrincipalRequest =
            serde_json::from_str(r#"{"ensure_browser":{"start_url":"https://example.com/"}}"#)
                .unwrap();
        assert_eq!(
            old,
            PrincipalRequest::EnsureBrowser {
                start_url: Some("https://example.com/".to_string()),
                headed: false,
                direct_cdp: false,
            }
        );
        let json = serde_json::to_string(&old).unwrap();
        assert!(!json.contains("headed"), "{json}");
    }

    #[test]
    fn ensure_browser_validates_start_url_bounds() {
        PrincipalRequest::EnsureBrowser {
            start_url: Some("https://example.com/".to_string()),
            headed: false,
            direct_cdp: false,
        }
        .validate()
        .unwrap();

        let empty = PrincipalRequest::EnsureBrowser {
            start_url: Some(String::new()),
            headed: false,
            direct_cdp: false,
        }
        .validate()
        .unwrap_err();
        assert!(empty.to_string().contains("start_url"));

        let oversized = PrincipalRequest::EnsureBrowser {
            start_url: Some(format!("https://example.com/{}", "a".repeat(4096))),
            headed: false,
            direct_cdp: false,
        }
        .validate()
        .unwrap_err();
        assert!(oversized.to_string().contains("start_url"));
    }

    #[test]
    fn browser_ensured_round_trips_with_endpoint() {
        let response = PrincipalResponse::BrowserEnsured(BrowserStatusResponse {
            running: true,
            status: "active".to_string(),
            cdp_endpoint: Some(
                "ws://127.0.0.1:43871/devtools/browser/00000000-0000-0000-0000-000000000000"
                    .to_string(),
            ),
            shared_browser_context: None,
            interception: Some("attached".to_string()),
            incognito_allowed: Some(true),
            cdp_exposure: Some("port".to_string()),
        });

        let json = serde_json::to_string(&response).unwrap();
        let decoded: PrincipalResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn direct_cdp_is_optional_on_the_wire() {
        let direct = PrincipalRequest::EnsureBrowser {
            start_url: None,
            headed: false,
            direct_cdp: true,
        };
        direct.validate().unwrap();
        let json = serde_json::to_string(&direct).unwrap();
        assert!(json.contains("\"direct_cdp\":true"), "{json}");
        assert_eq!(
            serde_json::from_str::<PrincipalRequest>(&json).unwrap(),
            direct
        );

        // The default (`agent browser`) is not sent, and a request without the field leaves it off.
        let plain = PrincipalRequest::EnsureBrowser {
            start_url: None,
            headed: false,
            direct_cdp: false,
        };
        assert!(
            !serde_json::to_string(&plain)
                .unwrap()
                .contains("direct_cdp")
        );
        assert_eq!(
            serde_json::from_str::<PrincipalRequest>(r#"{"ensure_browser":{}}"#).unwrap(),
            plain
        );
    }

    #[test]
    fn a_pipe_mode_browser_round_trips_without_an_endpoint() {
        let response = PrincipalResponse::BrowserEnsured(BrowserStatusResponse {
            running: true,
            status: "authentication_pending".to_string(),
            cdp_endpoint: None,
            shared_browser_context: None,
            interception: Some("attached".to_string()),
            incognito_allowed: Some(true),
            cdp_exposure: Some("pipe".to_string()),
        });
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("cdp_endpoint"), "{json}");
        assert!(json.contains("\"cdp_exposure\":\"pipe\""), "{json}");
        assert_eq!(
            serde_json::from_str::<PrincipalResponse>(&json).unwrap(),
            response
        );
    }
}
