//! Pass (password-store) backend configuration

use super::defaults;

crate::define_config! {
    /// Pass (password-store) backend configuration
    PassBackendConfig / PassBackendConfigArgs => group = "pass", prefix = "pass", env_prefix = "PASS" {
        (store_path, "STORE_PATH", "store-path": String = defaults::pass_store_path()
            => "Path to password store directory"
            , value_name = "PATH"),

        (path, "PATH", "path": String = defaults::PASS_PATH.to_string()
            => "Relative path within password store for FIDO2 entries"
            , value_name = "PATH"),

        (gpg_backend, "GPG_BACKEND", "gpg-backend": String = defaults::PASS_GPG_BACKEND.to_string()
            => "GPG backend: \"gpgme\" or \"gnupg-bin\""
            , value_name = "BACKEND"),
    }
}
