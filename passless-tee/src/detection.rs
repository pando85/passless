//! TEE detection implementation for Linux

use log::{debug, info, warn};
use std::fs;
use std::path::Path;

/// Supported TEE backends
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeBackend {
    /// No TEE support detected
    None,
    /// Intel SGX (Software Guard Extensions)
    IntelSgx,
    /// AMD SEV (Secure Encrypted Virtualization)
    AmdSev,
}

/// TEE capabilities and features
#[derive(Debug, Clone)]
pub struct TeeCapabilities {
    /// The detected TEE backend
    pub backend: TeeBackend,
    /// SGX: Enclave Page Cache size (bytes)
    pub sgx_epc_size: Option<usize>,
    /// SGX: Supports EDMM (Enclave Dynamic Memory Management)
    pub sgx_edmm: bool,
    /// SEV: SEV version (1, 2 for SEV-ES, 3 for SEV-SNP)
    pub sev_version: Option<u8>,
}

impl Default for TeeCapabilities {
    fn default() -> Self {
        Self {
            backend: TeeBackend::None,
            sgx_epc_size: None,
            sgx_edmm: false,
            sev_version: None,
        }
    }
}

impl TeeCapabilities {
    /// Check if TEE is available
    pub fn is_available(&self) -> bool {
        self.backend != TeeBackend::None
    }

    /// Check if SGX is available
    pub fn is_sgx_available(&self) -> bool {
        self.backend == TeeBackend::IntelSgx
    }

    /// Check if SEV is available
    pub fn is_sev_available(&self) -> bool {
        self.backend == TeeBackend::AmdSev
    }
}

/// Detect TEE capabilities on the current system
pub fn detect_tee() -> TeeCapabilities {
    let mut caps = TeeCapabilities::default();

    if detect_sgx(&mut caps) {
        info!("Intel SGX detected");
        return caps;
    }

    if detect_sev(&mut caps) {
        info!("AMD SEV detected");
        return caps;
    }

    debug!("No TEE support detected");
    caps
}

/// Detect Intel SGX support
fn detect_sgx(caps: &mut TeeCapabilities) -> bool {
    let sgx_dev = Path::new("/dev/sgx_enclave");
    let sgx_dev_dcap = Path::new("/dev/sgx/enclave");

    if !sgx_dev.exists() && !sgx_dev_dcap.exists() {
        debug!("No SGX device found");
        return false;
    }

    debug!("SGX device found");

    if !check_cpu_flag("sgx") {
        warn!("SGX device exists but CPU flag 'sgx' not found");
        return false;
    }

    caps.sgx_epc_size = detect_epc_size();
    caps.sgx_edmm = check_cpu_flag("sgxlc");
    caps.backend = TeeBackend::IntelSgx;
    true
}

/// Detect AMD SEV support
fn detect_sev(caps: &mut TeeCapabilities) -> bool {
    let sev_param = Path::new("/sys/module/kvm_amd/parameters/sev");
    let snp_param = Path::new("/sys/module/kvm_amd/parameters/sev_snp");

    if !sev_param.exists() {
        debug!("SEV kernel module parameter not found");
        return false;
    }

    let Ok(content) = fs::read_to_string(sev_param) else {
        return false;
    };

    if content.trim() != "Y" {
        debug!("SEV not enabled in kernel");
        return false;
    }

    caps.sev_version = Some(1);

    if let Ok(content) = fs::read_to_string("/sys/module/kvm_amd/parameters/sev_es")
        && content.trim() == "Y"
    {
        caps.sev_version = Some(2);
    }

    if snp_param.exists()
        && let Ok(content) = fs::read_to_string(snp_param)
        && content.trim() == "Y"
    {
        caps.sev_version = Some(3);
    }

    caps.backend = TeeBackend::AmdSev;
    true
}

/// Check if a CPU flag is present
#[allow(clippy::collapsible_if)]
fn check_cpu_flag(flag: &str) -> bool {
    let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") else {
        warn!("Failed to read /proc/cpuinfo");
        return false;
    };

    for line in cpuinfo.lines() {
        if line.starts_with("flags") {
            if let Some(flags) = line.split(':').nth(1) {
                return flags.split_whitespace().any(|f| f == flag);
            }
        }
    }

    false
}

/// Detect SGX EPC (Enclave Page Cache) size
#[allow(clippy::collapsible_if)]
fn detect_epc_size() -> Option<usize> {
    let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") else {
        return None;
    };

    for line in cpuinfo.lines() {
        if line.starts_with("sgx_epc_sections") {
            if let Some(size_str) = line.split(':').nth(1) {
                if let Ok(size) = size_str.trim().parse::<usize>() {
                    return Some(size);
                }
            }
        }
    }

    debug!("Could not determine EPC size, using default estimate");
    Some(128 * 1024 * 1024)
}

/// Check if running inside a Gramine SGX enclave
#[allow(dead_code)]
pub fn is_gramine_sgx() -> bool {
    std::env::var("GRAMINE").is_ok() || std::env::var("SGX").is_ok()
}

/// Check if SGX attestation is available
#[allow(dead_code)]
pub fn is_attestation_available() -> bool {
    Path::new("/dev/sgx/attestation").exists()
        || Path::new("/dev/sgx_attestation").exists()
        || Path::new("/dev/sgx_isv").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tee_backend_equality() {
        assert_eq!(TeeBackend::None, TeeBackend::None);
        assert_eq!(TeeBackend::IntelSgx, TeeBackend::IntelSgx);
        assert_ne!(TeeBackend::IntelSgx, TeeBackend::AmdSev);
    }

    #[test]
    fn test_tee_capabilities_default() {
        let caps = TeeCapabilities::default();
        assert_eq!(caps.backend, TeeBackend::None);
        assert!(!caps.is_available());
    }

    #[test]
    fn test_tee_capabilities_sgx() {
        let mut caps = TeeCapabilities::default();
        caps.backend = TeeBackend::IntelSgx;
        assert!(caps.is_available());
        assert!(caps.is_sgx_available());
        assert!(!caps.is_sev_available());
    }

    #[test]
    fn test_detect_tee() {
        let caps = detect_tee();
        match caps.backend {
            TeeBackend::None | TeeBackend::IntelSgx | TeeBackend::AmdSev => {}
        }
    }
}
