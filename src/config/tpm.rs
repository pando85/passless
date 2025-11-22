//! TPM (Trusted Platform Module) backend configuration

use super::defaults;

crate::define_config! {
    /// TPM (Trusted Platform Module) backend configuration
    TpmBackendConfig / TpmBackendConfigArgs => group = "tpm", prefix = "tpm", env_prefix = "TPM" {
        (path, "PATH", "path": String = defaults::tpm_path()
            => "Path to TPM storage directory"
            , value_name = "PATH"),

        (tcti, "TCTI", "tcti": String = defaults::TPM_TCTI.to_string()
            => "TPM TCTI (TPM Command Transmission Interface) configuration"
            , value_name = "TCTI"),
    }
}
