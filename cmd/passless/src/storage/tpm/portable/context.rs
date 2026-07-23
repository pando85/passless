//! TPM context creation helper

use tss_esapi::{Context, Tcti};

/// Create a TPM context from an optional TCTI configuration string.
///
/// If `tcti` is `Some(s)`, parses `s` as a TCTI configuration.
/// If `tcti` is `None`, uses the default TCTI (device:/dev/tpmrm0).
///
/// Returns the raw `tss_esapi::Error` so callers can map to their own error types
/// and add their own log messages.
pub(crate) fn create_tpm_context(
    tcti: Option<&str>,
) -> core::result::Result<Context, tss_esapi::Error> {
    let tcti_conf = match tcti {
        Some(s) => std::str::FromStr::from_str(s)?,
        None => Tcti::Device(Default::default()),
    };
    Context::new(tcti_conf)
}
