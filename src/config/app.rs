//! Application-level configuration

use super::defaults;
use super::local::LocalBackendConfig;
use super::pass::PassBackendConfig;
use super::security::SecurityConfig;
use super::state::{ConfigState, Field, Raw, Resolved, StateMarker};
use super::tpm::TpmBackendConfig;

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Storage backend configuration (type-safe enum for Resolved state)
#[derive(Debug, Clone)]
pub enum BackendConfig {
    /// Local file system storage
    Local(LocalBackendConfig<Resolved>),
    /// Pass (password-store) backend
    Pass(PassBackendConfig<Resolved>),
    /// TPM (Trusted Platform Module) backend
    Tpm(TpmBackendConfig<Resolved>),
}

/// Application-level configuration
#[derive(Debug, Clone)]
pub struct AppConfig<State: ConfigState = Resolved> {
    /// Backend type: "local", "pass", or "tpm"
    pub backend_type: Field<State, String>,

    /// Enable verbose logging
    pub verbose: Field<State, bool>,

    /// Local backend configuration
    pub local: LocalBackendConfig<State>,

    /// Pass backend configuration
    pub pass: PassBackendConfig<State>,

    /// TPM backend configuration
    pub tpm: TpmBackendConfig<State>,

    /// Security hardening configuration
    pub security: SecurityConfig<State>,

    pub(crate) _state: StateMarker<State>,
}

impl Serialize for AppConfig<Raw> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AppConfig", 6)?;
        state.serialize_field("backend_type", &self.backend_type)?;
        state.serialize_field("verbose", &self.verbose)?;
        state.serialize_field("local", &self.local)?;
        state.serialize_field("pass", &self.pass)?;
        state.serialize_field("tpm", &self.tpm)?;
        state.serialize_field("security", &self.security)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AppConfig<Raw> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct AppConfigHelper {
            #[serde(default = "default_backend_type")]
            backend_type: Option<String>,
            #[serde(default)]
            verbose: Option<bool>,
            #[serde(default)]
            local: LocalBackendConfig<Raw>,
            #[serde(default)]
            pass: PassBackendConfig<Raw>,
            #[serde(default)]
            tpm: TpmBackendConfig<Raw>,
            #[serde(default)]
            security: SecurityConfig<Raw>,
        }

        let helper = AppConfigHelper::deserialize(deserializer)?;
        Ok(AppConfig {
            backend_type: helper.backend_type,
            verbose: helper.verbose,
            local: helper.local,
            pass: helper.pass,
            tpm: helper.tpm,
            security: helper.security,
            _state: StateMarker::new(),
        })
    }
}

fn default_backend_type() -> Option<String> {
    Some(defaults::BACKEND_TYPE.to_string())
}

impl<State: ConfigState> Default for AppConfig<State>
where
    Field<State, String>: Default,
    Field<State, bool>: Default,
{
    fn default() -> Self {
        Self {
            backend_type: Field::<State, String>::default(),
            verbose: Field::<State, bool>::default(),
            local: LocalBackendConfig::default(),
            pass: PassBackendConfig::default(),
            tpm: TpmBackendConfig::default(),
            security: SecurityConfig::default(),
            _state: StateMarker::new(),
        }
    }
}

impl AppConfig<Raw> {
    /// Create a new raw config (useful for CLI args)
    pub fn new(
        backend_type: Option<String>,
        verbose: Option<bool>,
        local: LocalBackendConfig<Raw>,
        pass: PassBackendConfig<Raw>,
        tpm: TpmBackendConfig<Raw>,
        security: SecurityConfig<Raw>,
    ) -> Self {
        Self {
            backend_type,
            verbose,
            local,
            pass,
            tpm,
            security,
            _state: StateMarker::new(),
        }
    }

    /// Load configuration from a TOML file
    pub fn from_toml(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;
        let config: AppConfig<Raw> = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config file {}: {}", path.display(), e))?;
        Ok(config)
    }

    /// Merge with another raw config, preferring override values
    pub fn merge(self, other: Self) -> Self {
        Self {
            backend_type: other.backend_type.or(self.backend_type),
            verbose: other.verbose.or(self.verbose),
            local: self.local.merge(other.local),
            pass: self.pass.merge(other.pass),
            tpm: self.tpm.merge(other.tpm),
            security: self.security.merge(other.security),
            _state: StateMarker::new(),
        }
    }

    /// Resolve to a concrete config with all defaults applied
    pub fn resolve(self) -> AppConfig<Resolved> {
        AppConfig {
            backend_type: self
                .backend_type
                .unwrap_or_else(|| defaults::BACKEND_TYPE.to_string()),
            verbose: self.verbose.unwrap_or(defaults::VERBOSE),
            local: self.local.resolve(),
            pass: self.pass.resolve(),
            tpm: self.tpm.resolve(),
            security: self.security.resolve(),
            _state: StateMarker::new(),
        }
    }
}

impl AppConfig<Resolved> {
    /// Get the active backend configuration as an enum
    pub fn backend(&self) -> crate::error::Result<BackendConfig> {
        match self.backend_type.as_str() {
            "local" => Ok(BackendConfig::Local(self.local.clone())),
            "pass" => Ok(BackendConfig::Pass(self.pass.clone())),
            "tpm" => Ok(BackendConfig::Tpm(self.tpm.clone())),
            _ => Err(crate::error::Error::Config(format!(
                "Invalid backend_type '{}'. Must be one of: local, pass, tpm",
                self.backend_type
            ))),
        }
    }

    /// Create a config with all defaults for display purposes
    pub fn with_defaults_filled() -> Self {
        Self {
            backend_type: defaults::BACKEND_TYPE.to_string(),
            verbose: defaults::VERBOSE,
            local: LocalBackendConfig {
                path: defaults::local_path_display(),
                _state: StateMarker::new(),
            },
            pass: PassBackendConfig {
                store_path: defaults::pass_store_path(),
                path: defaults::PASS_PATH.to_string(),
                gpg_backend: defaults::PASS_GPG_BACKEND.to_string(),
                _state: StateMarker::new(),
            },
            tpm: TpmBackendConfig {
                path: defaults::tpm_path_display(),
                tcti: defaults::TPM_TCTI.to_string(),
                _state: StateMarker::new(),
            },
            security: SecurityConfig {
                use_mlock: defaults::SECURITY_USE_MLOCK,
                disable_core_dumps: defaults::SECURITY_DISABLE_CORE_DUMPS,
                constant_signature_counter: defaults::SECURITY_CONSTANT_SIGNATURE_COUNTER,
                user_verification_registration: defaults::SECURITY_USER_VERIFICATION_REGISTRATION,
                user_verification_authentication:
                    defaults::SECURITY_USER_VERIFICATION_AUTHENTICATION,
                _state: StateMarker::new(),
            },
            _state: StateMarker::new(),
        }
    }
}

impl Serialize for AppConfig<Resolved> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AppConfig", 6)?;
        state.serialize_field("backend_type", &self.backend_type)?;
        state.serialize_field("verbose", &self.verbose)?;

        // Serialize resolved configs as if they were Raw (with Some values)
        let mut local_map = serde_json::Map::new();
        local_map.insert(
            "path".to_string(),
            serde_json::Value::String(self.local.path.clone()),
        );
        state.serialize_field("local", &local_map)?;

        let mut pass_map = serde_json::Map::new();
        pass_map.insert(
            "store_path".to_string(),
            serde_json::Value::String(self.pass.store_path.clone()),
        );
        pass_map.insert(
            "path".to_string(),
            serde_json::Value::String(self.pass.path.clone()),
        );
        pass_map.insert(
            "gpg_backend".to_string(),
            serde_json::Value::String(self.pass.gpg_backend.clone()),
        );
        state.serialize_field("pass", &pass_map)?;

        let mut tpm_map = serde_json::Map::new();
        tpm_map.insert(
            "path".to_string(),
            serde_json::Value::String(self.tpm.path.clone()),
        );
        tpm_map.insert(
            "tcti".to_string(),
            serde_json::Value::String(self.tpm.tcti.clone()),
        );
        state.serialize_field("tpm", &tpm_map)?;

        let mut security_map = serde_json::Map::new();
        security_map.insert(
            "use_mlock".to_string(),
            serde_json::Value::Bool(self.security.use_mlock),
        );
        security_map.insert(
            "disable_core_dumps".to_string(),
            serde_json::Value::Bool(self.security.disable_core_dumps),
        );
        security_map.insert(
            "constant_signature_counter".to_string(),
            serde_json::Value::Bool(self.security.constant_signature_counter),
        );
        security_map.insert(
            "user_verification_registration".to_string(),
            serde_json::Value::Bool(self.security.user_verification_registration),
        );
        security_map.insert(
            "user_verification_authentication".to_string(),
            serde_json::Value::Bool(self.security.user_verification_authentication),
        );
        state.serialize_field("security", &security_map)?;

        state.end()
    }
}
