//! Default configuration values

/// Default backend type
pub const BACKEND_TYPE: &str = "local";

/// Default verbose setting
pub const VERBOSE: bool = false;

/// Default value for use_mlock security setting
pub const SECURITY_USE_MLOCK: bool = true;

/// Default value for disable_core_dumps security setting
pub const SECURITY_DISABLE_CORE_DUMPS: bool = true;

/// Default value for user verification during registration
pub const USER_VERIFICATION_REGISTRATION: bool = true;

/// Default value for user verification during authentication
pub const USER_VERIFICATION_AUTHENTICATION: bool = true;

/// Default relative path within password-store for FIDO2 credentials
pub const PASS_PATH: &str = "fido2";

/// Default GPG backend
pub const PASS_GPG_BACKEND: &str = "gnupg-bin";

/// Default TPM TCTI (TPM Command Transmission Interface)
pub const TPM_TCTI: &str = "device:/dev/tpmrm0";

/// Compute default local storage path
pub fn local_path() -> String {
    dirs::data_dir()
        .expect("Could not determine data directory: $XDG_DATA_HOME or $HOME/.local/share")
        .join("passless")
        .to_string_lossy()
        .into_owned()
}

/// Compute default local storage path, with fallback for display purposes
pub fn local_path_display() -> String {
    dirs::data_dir()
        .map(|p| p.join("passless").to_string_lossy().into_owned())
        .unwrap_or_else(|| "$XDG_DATA_HOME/passless or $HOME/.local/share/passless".to_string())
}

/// Compute default password-store path
pub fn pass_store_path() -> String {
    dirs::home_dir()
        .expect("Could not determine home directory: $HOME")
        .join(".password-store")
        .to_string_lossy()
        .into_owned()
}

/// Compute default TPM storage path
pub fn tpm_path() -> String {
    dirs::data_dir()
        .expect("Could not determine data directory: $XDG_DATA_HOME or $HOME/.local/share")
        .join("passless/tpm")
        .to_string_lossy()
        .into_owned()
}

/// Compute default TPM storage path, with fallback for display purposes
pub fn tpm_path_display() -> String {
    dirs::data_dir()
        .map(|p| p.join("passless/tpm").to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            "$XDG_DATA_HOME/passless/tpm or $HOME/.local/share/passless/tpm".to_string()
        })
}
