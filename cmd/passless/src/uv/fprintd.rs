//! fprintd-based User Verification Provider
//!
//! Uses the fprintd D-Bus service for fingerprint verification.
//!
//! # Requirements
//!
//! - fprintd service must be running
//! - A fingerprint reader must be connected
//! - User must have enrolled fingerprints

use super::{
    UserVerificationProvider, VerificationContext, VerificationError, VerificationResult, priority,
};

use log::{debug, error, info, warn};

use std::sync::Arc;
use std::sync::Mutex;

/// fprintd-based fingerprint verification provider
pub struct FprintdProvider {
    runtime: Mutex<Option<Arc<tokio::runtime::Runtime>>>,
}

impl FprintdProvider {
    /// Create a new fprintd provider
    pub fn new() -> Self {
        Self {
            runtime: Mutex::new(None),
        }
    }

    /// Create a provider if enabled in config
    pub fn from_config(enabled: bool) -> Option<Box<dyn UserVerificationProvider>> {
        if enabled {
            Some(Box::new(Self::new()))
        } else {
            None
        }
    }

    /// Get or create the tokio runtime
    fn get_runtime(&self) -> Result<Arc<tokio::runtime::Runtime>, VerificationError> {
        let mut runtime_guard = self.runtime.lock().unwrap();
        if runtime_guard.is_none() {
            *runtime_guard = Some(Arc::new(tokio::runtime::Runtime::new().map_err(|e| {
                VerificationError::DeviceError(format!("Failed to create runtime: {}", e))
            })?));
        }
        Ok(runtime_guard.as_ref().unwrap().clone())
    }

    async fn do_verify(timeout_secs: u32) -> Result<VerificationResult, VerificationError> {
        use zbus::Connection;

        debug!("Starting fprintd verification");

        let conn = Connection::system().await.map_err(|e| {
            VerificationError::DeviceError(format!("D-Bus connection failed: {}", e))
        })?;

        let device_path: zbus::OwnedObjectPath = conn
            .call_method(
                Some("net.reactivated.Fprint"),
                "/net/reactivated/Fprint/Manager",
                Some("net.reactivated.Fprint.Manager"),
                "GetDefaultDevice",
                &(),
            )
            .await
            .map_err(|e| VerificationError::NotAvailable(format!("No fingerprint device: {}", e)))?
            .body()
            .deserialize()
            .map_err(|e| VerificationError::DeviceError(format!("Invalid response: {}", e)))?;

        debug!("Found device at path: {:?}", device_path);

        // D-Bus broadcasts can be emitted by other clients. Bind VerifyStatus to
        // the unique owner of the fprintd service, not just its interface/path.
        let service_owner: String = conn
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "GetNameOwner",
                &"net.reactivated.Fprint",
            )
            .await
            .map_err(|e| {
                VerificationError::DeviceError(format!("fprintd owner lookup failed: {}", e))
            })?
            .body()
            .deserialize()
            .map_err(|e| VerificationError::DeviceError(format!("Invalid fprintd owner: {}", e)))?;

        conn.call_method(
            Some("net.reactivated.Fprint"),
            device_path.as_str(),
            Some("net.reactivated.Fprint.Device"),
            "Claim",
            &"",
        )
        .await
        .map_err(|e| VerificationError::DeviceError(format!("Failed to claim device: {}", e)))?;

        let result =
            Self::wait_for_verification(&conn, &device_path, &service_owner, timeout_secs).await;

        let _ = conn
            .call_method(
                Some("net.reactivated.Fprint"),
                device_path.as_str(),
                Some("net.reactivated.Fprint.Device"),
                "Release",
                &(),
            )
            .await;

        result
    }

    async fn wait_for_verification(
        conn: &zbus::Connection,
        device_path: &zbus::OwnedObjectPath,
        service_owner: &str,
        timeout_secs: u32,
    ) -> Result<VerificationResult, VerificationError> {
        use futures_util::StreamExt;
        use zbus::MessageStream;

        // Subscribe BEFORE starting verification so a fast VerifyStatus signal
        // cannot race the creation of the receiver.
        let mut stream = MessageStream::from(conn);
        conn.call_method(
            Some("net.reactivated.Fprint"),
            device_path.as_str(),
            Some("net.reactivated.Fprint.Device"),
            "VerifyStart",
            &"any",
        )
        .await
        .map_err(|e| {
            VerificationError::DeviceError(format!("Failed to start verification: {}", e))
        })?;

        let timeout = tokio::time::sleep(std::time::Duration::from_secs(timeout_secs as u64));
        tokio::pin!(timeout);

        let mut result = VerificationResult::Timeout;
        let mut provider_error: Option<VerificationError> = None;

        loop {
            tokio::select! {
                _ = &mut timeout => {
                    warn!("Fingerprint verification timed out");
                    break;
                }
                msg = stream.next() => {
                    match msg {
                        Some(Ok(msg)) => {
                            let header = msg.header();
                            if !Self::is_expected_sender(
                                service_owner,
                                header.sender().map(|s| s.as_str()),
                            ) {
                                continue;
                            }

                            if header.interface().map(|i| i.as_str()) != Some("net.reactivated.Fprint.Device") {
                                continue;
                            }
                            if header.member().map(|m| m.as_str()) != Some("VerifyStatus") {
                                continue;
                            }
                            if header.path().map(|p| p.as_str()) != Some(device_path.as_str()) {
                                continue;
                            }

                            match msg.body().deserialize::<(&str, bool)>() {
                                Ok((status, done)) => {
                                    debug!("fprintd status: {}", status);

                                    match status {
                                        "verify-match" if done => {
                                            info!("Fingerprint matched");
                                            result = VerificationResult::Accepted;
                                            break;
                                        }
                                        "verify-match" => continue,
                                        "verify-no-match" if done => {
                                            info!("Fingerprint not matched");
                                            result = VerificationResult::Denied;
                                            break;
                                        }
                                        "verify-no-match" => continue,
                                        "verify-retry-scan"
                                        | "verify-swipe-too-short"
                                        | "verify-finger-not-entered"
                                        | "verify-finger-not-centered"
                                        | "verify-too-fast"
                                        | "verify-remove-and-retry" => {
                                            debug!("Retry requested: {}", status);
                                            continue;
                                        }
                                        "verify-disconnected" => {
                                            error!("Fingerprint device disconnected");
                                            provider_error = Some(VerificationError::DeviceError(
                                                "Fingerprint device disconnected".into(),
                                            ));
                                            break;
                                        }
                                        "verify-unknown-error" => {
                                            error!("Fingerprint device returned an error");
                                            provider_error = Some(VerificationError::DeviceError(
                                                "Fingerprint device returned an error".into(),
                                            ));
                                            break;
                                        }
                                        _ => {
                                            warn!("Unknown status: {}", status);
                                            continue;
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to parse signal: {}", e);
                                    continue;
                                }
                            }
                        }
                        Some(Err(e)) => {
                            error!("Error receiving fingerprint signal: {}", e);
                            provider_error = Some(VerificationError::DeviceError(e.to_string()));
                            break;
                        }
                        None => {
                            error!("Fingerprint signal stream closed");
                            provider_error = Some(VerificationError::DeviceError(
                                "Fingerprint signal stream closed".into(),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        let _ = conn
            .call_method(
                Some("net.reactivated.Fprint"),
                device_path.as_str(),
                Some("net.reactivated.Fprint.Device"),
                "VerifyStop",
                &(),
            )
            .await;

        if let Some(error) = provider_error {
            Err(error)
        } else {
            Ok(result)
        }
    }

    fn is_expected_sender(owner: &str, sender: Option<&str>) -> bool {
        sender == Some(owner)
    }

    fn check_enrolled(&self) -> bool {
        let rt = match self.get_runtime() {
            Ok(rt) => rt,
            Err(_) => return false,
        };
        rt.block_on(async {
            use zbus::Connection;
            let Ok(conn) = Connection::system().await else {
                return false;
            };
            let Ok(reply) = conn
                .call_method(
                    Some("net.reactivated.Fprint"),
                    "/net/reactivated/Fprint/Manager",
                    Some("net.reactivated.Fprint.Manager"),
                    "GetDefaultDevice",
                    &(),
                )
                .await
            else {
                return false;
            };
            let Ok(path) = reply.body().deserialize::<zbus::OwnedObjectPath>() else {
                return false;
            };
            let Ok(reply) = conn
                .call_method(
                    Some("net.reactivated.Fprint"),
                    path.as_str(),
                    Some("net.reactivated.Fprint.Device"),
                    "ListEnrolledFingers",
                    &"",
                )
                .await
            else {
                return false;
            };
            reply
                .body()
                .deserialize::<Vec<String>>()
                .map(|fingers| !fingers.is_empty())
                .unwrap_or(false)
        })
    }

    fn check_available(&self) -> bool {
        let rt = match self.get_runtime() {
            Ok(rt) => rt,
            Err(_) => return false,
        };

        rt.block_on(async {
            use zbus::Connection;

            match Connection::system().await {
                Ok(conn) => {
                    match conn
                        .call_method(
                            Some("net.reactivated.Fprint"),
                            "/net/reactivated/Fprint/Manager",
                            Some("net.reactivated.Fprint.Manager"),
                            "GetDefaultDevice",
                            &(),
                        )
                        .await
                    {
                        Ok(reply) => {
                            if let Ok(path) = reply.body().deserialize::<zbus::OwnedObjectPath>() {
                                info!("fprintd device available at: {:?}", path);
                                true
                            } else {
                                false
                            }
                        }
                        Err(_) => false,
                    }
                }
                Err(_) => false,
            }
        })
    }
}

impl Default for FprintdProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl UserVerificationProvider for FprintdProvider {
    fn name(&self) -> &str {
        "fprintd"
    }

    fn available(&self) -> bool {
        // Device hotplug and fprintd restarts must not leave stale cache entries.
        self.check_available()
    }

    fn verify(
        &self,
        context: &VerificationContext,
    ) -> Result<VerificationResult, VerificationError> {
        let timeout_secs = context.timeout_seconds;
        let rt = self.get_runtime()?;

        rt.block_on(async { Self::do_verify(timeout_secs).await })
    }

    fn priority(&self) -> u8 {
        priority::FPRINTD
    }

    fn supports_strong_uv(&self) -> bool {
        true
    }

    fn supports_enrollment(&self) -> bool {
        true
    }

    fn requires_enrollment(&self) -> bool {
        true
    }

    fn is_enrolled(&self) -> bool {
        self.check_enrolled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_forged_fprintd_status_sender() {
        assert!(FprintdProvider::is_expected_sender(":1.42", Some(":1.42")));
        assert!(!FprintdProvider::is_expected_sender(":1.42", Some(":1.43")));
        assert!(!FprintdProvider::is_expected_sender(":1.42", None));
        assert!(!FprintdProvider::is_expected_sender(
            ":1.42",
            Some("net.reactivated.Fprint")
        ));
    }

    #[test]
    fn test_fprintd_provider_name() {
        let provider = FprintdProvider::new();
        assert_eq!(provider.name(), "fprintd");
    }

    #[test]
    fn test_fprintd_provider_priority() {
        let provider = FprintdProvider::new();
        assert_eq!(provider.priority(), priority::FPRINTD);
    }

    #[test]
    fn test_fprintd_provider_supports_enrollment() {
        let provider = FprintdProvider::new();
        assert!(provider.supports_enrollment());
    }
}
