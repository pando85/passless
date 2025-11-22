//! Local storage backend configuration

use super::defaults;

crate::define_config! {
    /// Local storage backend configuration
    LocalBackendConfig / LocalBackendConfigArgs => group = "local", prefix = "local", env_prefix = "LOCAL" {
        (path, "PATH", "path": String = defaults::local_path()
            => "Path to storage directory"
            , value_name = "PATH"),
    }
}
