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
    available_cache: Mutex<Option<bool>>,
    runtime: Mutex<Option<Arc<tokio::runtime::Runtime>>>,
}

impl FprintdProvider {
    /// Create a new fprintd provider
    pub fn new() -> Self {
        Self {
            available_cache: Mutex::new(None),
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

        let device_path: zbus::zvariant::OwnedObjectPath = conn
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

        conn.call_method(
            Some("net.reactivated.Fprint"),
            device_path.as_str(),
            Some("net.reactivated.Fprint.Device"),
            "Claim",
            &"",
        )
        .await
        .map_err(|e| VerificationError::DeviceError(format!("Failed to claim device: {}", e)))?;

        let result = Self::wait_for_verification(&conn, &device_path, timeout_secs).await;

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
        device_path: &zbus::zvariant::OwnedObjectPath,
        timeout_secs: u32,
    ) -> Result<VerificationResult, VerificationError> {
        use futures_util::StreamExt;
        use zbus::MessageStream;

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

        let mut stream = MessageStream::from(conn);

        let timeout = tokio::time::sleep(std::time::Duration::from_secs(timeout_secs as u64));
        tokio::pin!(timeout);

        let mut result = VerificationResult::Timeout;

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
                                Ok((status, _done)) => {
                                    debug!("fprintd status: {}", status);

                                    match status {
                                        "verify-match" => {
                                            info!("Fingerprint matched");
                                            result = VerificationResult::Accepted;
                                            break;
                                        }
                                        "verify-no-match" => {
                                            info!("Fingerprint not matched");
                                            result = VerificationResult::Denied;
                                            break;
                                        }
                                        "verify-retry-scan"
                                        | "verify-swipe-too-short"
                                        | "verify-finger-not-entered"
                                        | "verify-remove-and-retry" => {
                                            debug!("Retry requested: {}", status);
                                            continue;
                                        }
                                        "verify-disconnected" => {
                                            error!("Device disconnected");
                                            result = VerificationResult::Denied;
                                            break;
                                        }
                                        "verify-unknown-error" => {
                                            error!("Unknown error");
                                            result = VerificationResult::Denied;
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
                            error!("Error receiving message: {}", e);
                            continue;
                        }
                        None => {
                            error!("Signal stream closed");
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

        Ok(result)
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
                            if let Ok(path) = reply
                                .body()
                                .deserialize::<zbus::zvariant::OwnedObjectPath>()
                            {
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
        if let Some(cached) = *self.available_cache.lock().unwrap() {
            return cached;
        }

        let available = self.check_available();
        *self.available_cache.lock().unwrap() = Some(available);
        available
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

    fn supports_enrollment(&self) -> bool {
        true
    }

    fn requires_enrollment(&self) -> bool {
        true
    }

    fn is_enrolled(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
