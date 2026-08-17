#![cfg(feature = "agent")]

use passless_core::agent::protocol::{
    BrowserStatusResponse, PrincipalRequest, PrincipalResponse, Validate, CURRENT_VERSION,
};

#[test]
fn protocol_minor_version_covers_ensure_browser() {
    assert_eq!(CURRENT_VERSION.major, 1);
    assert!(CURRENT_VERSION.minor >= 2);
}

#[test]
fn ensure_browser_round_trips_without_start_url() {
    let request = PrincipalRequest::EnsureBrowser { start_url: None };
    request.validate().unwrap();

    let json = serde_json::to_string(&request).unwrap();
    let decoded: PrincipalRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn ensure_browser_validates_start_url_bounds() {
    PrincipalRequest::EnsureBrowser {
        start_url: Some("https://example.com/".to_string()),
    }
    .validate()
    .unwrap();

    let empty = PrincipalRequest::EnsureBrowser {
        start_url: Some(String::new()),
    }
    .validate()
    .unwrap_err();
    assert!(empty.to_string().contains("start_url"));

    let oversized = PrincipalRequest::EnsureBrowser {
        start_url: Some(format!("https://example.com/{}", "a".repeat(4096))),
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
    });

    let json = serde_json::to_string(&response).unwrap();
    let decoded: PrincipalResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, response);
}
