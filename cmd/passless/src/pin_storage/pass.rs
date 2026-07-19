//! Pass (password-store) PIN storage

use crate::pin_storage::{
    PinStorage, SerializablePinConfig, SerializablePinRetries, SerializablePinState,
};
use crate::storage::pass::GpgBackend;
use crate::util::create_secure_dir_all;

use passless_core::error::{Error, Result};

use std::path::PathBuf;
use std::sync::RwLock;

use log::{debug, info, warn};
use prs_lib::crypto::IsContext;
use prs_lib::{Ciphertext, Plaintext, Store};

const PIN_CONFIG_ENTRY: &str = "pin_state";
const PIN_RETRIES_ENTRY: &str = "pin_retries";

/// Tracked state for conflict detection
#[derive(Debug, Clone)]
struct SyncedConfig {
    version: u64,
    #[allow(dead_code)]
    modified_at: Option<u64>,
    pin_hash: Option<Vec<u8>>,
}

/// Pass (password-store) PIN storage
///
/// Stores PIN state as two GPG-encrypted entries in the password store:
/// - `pin_state.gpg`: PIN config (hash, min length, version) - synced to git
/// - `pin_retries.gpg`: Retry counters (retries, uv_retries, locked_until) - local only
pub struct PassPinStorage {
    store_path: PathBuf,
    fido2_path: PathBuf,
    gpg_backend: GpgBackend,
    /// Last known config state for change detection (for git sync optimization)
    last_config: RwLock<Option<SerializablePinConfig>>,
    /// Last synced config state for conflict detection
    last_synced: RwLock<Option<SyncedConfig>>,
}

impl PassPinStorage {
    /// Create a new Pass PIN storage
    pub fn new(store_path: PathBuf, fido2_path: PathBuf, gpg_backend: GpgBackend) -> Self {
        debug!(
            "Pass PIN storage: store={}, path={}",
            store_path.display(),
            fido2_path.display()
        );
        Self {
            store_path,
            fido2_path,
            gpg_backend,
            last_config: RwLock::new(None),
            last_synced: RwLock::new(None),
        }
    }

    fn get_config_path(&self) -> PathBuf {
        self.store_path
            .join(&self.fido2_path)
            .join(format!("{}.gpg", PIN_CONFIG_ENTRY))
    }

    fn get_retries_path(&self) -> PathBuf {
        self.store_path
            .join(&self.fido2_path)
            .join(format!("{}.gpg", PIN_RETRIES_ENTRY))
    }

    fn create_crypto_context(&self) -> Result<prs_lib::crypto::Context> {
        let proto = match self.gpg_backend {
            GpgBackend::Gpgme | GpgBackend::GnupgBin => prs_lib::crypto::Proto::Gpg,
        };

        let config = prs_lib::crypto::Config::from(proto);
        prs_lib::crypto::context(&config).map_err(|e| {
            warn!("Failed to create crypto context: {:?}", e);
            Error::Storage(format!("Failed to create crypto context: {:?}", e))
        })
    }

    fn load_recipients_from_gpg_id(&self) -> Result<prs_lib::Recipients> {
        let gpg_id_path = self.store_path.join(".gpg-id");
        match std::fs::read_to_string(&gpg_id_path) {
            Ok(content) => {
                let keys: Vec<prs_lib::Key> = content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(|key_id| {
                        let gpg_key = prs_lib::crypto::proto::gpg::Key {
                            fingerprint: key_id.to_string(),
                            user_ids: vec![],
                        };
                        prs_lib::Key::Gpg(gpg_key)
                    })
                    .collect();

                if keys.is_empty() {
                    return Err(Error::Storage(format!(
                        "No GPG key IDs found in {:?}",
                        gpg_id_path
                    )));
                }

                Ok(prs_lib::Recipients::from(keys))
            }
            Err(e) => Err(Error::Storage(format!(
                "Failed to read {:?}: {}",
                gpg_id_path, e
            ))),
        }
    }

    fn sync_prepare(&self) -> Result<()> {
        debug!("Preparing password store sync for PIN config");

        let store = Store::open(self.store_path.to_string_lossy().as_ref()).map_err(|e| {
            debug!("Failed to open store for sync: {:?}", e);
            Error::Storage(format!("Failed to open store for sync: {:?}", e))
        })?;

        let sync = store.sync();

        match sync.prepare() {
            Ok(()) => {
                debug!("Successfully prepared store sync (pulled if remote configured)");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to prepare store sync: {:?}", e);
                Ok(())
            }
        }
    }

    fn sync_finalize(&self, message: &str) -> Result<()> {
        debug!("Finalizing password store sync: {}", message);

        let store = Store::open(self.store_path.to_string_lossy().as_ref()).map_err(|e| {
            debug!("Failed to open store for sync: {:?}", e);
            Error::Storage(format!("Failed to open store for sync: {:?}", e))
        })?;

        let sync = store.sync();

        match sync.finalize(message) {
            Ok(()) => {
                debug!(
                    "Successfully finalized store sync (committed and pushed if remote configured)"
                );
                Ok(())
            }
            Err(e) => {
                debug!("Failed to finalize store sync: {:?}", e);
                warn!("Failed to finalize store sync: {:?}", e);
                Ok(())
            }
        }
    }

    fn load_config(&self) -> std::result::Result<SerializablePinConfig, soft_fido2::StatusCode> {
        debug!("Loading PIN config from pass store");

        let path = self.get_config_path();

        if !path.exists() {
            debug!("PIN config entry does not exist, returning default state");
            return Ok(SerializablePinConfig::default());
        }

        let encrypted_data = std::fs::read(&path).map_err(|e| {
            warn!("Failed to read PIN config entry: {}", e);
            soft_fido2::StatusCode::Other
        })?;

        let mut context = self.create_crypto_context().map_err(|e| {
            warn!("Failed to create crypto context: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        let ciphertext = Ciphertext::from(encrypted_data);
        let plaintext = context.decrypt(ciphertext).map_err(|e| {
            warn!("Failed to decrypt PIN config: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        SerializablePinConfig::from_json_bytes(plaintext.unsecure_ref()).map_err(|e| {
            warn!("Failed to parse PIN config: {:?}", e);
            soft_fido2::StatusCode::InvalidParameter
        })
    }

    fn load_retries(&self) -> std::result::Result<SerializablePinRetries, soft_fido2::StatusCode> {
        debug!("Loading PIN retries from pass store");

        let path = self.get_retries_path();

        if !path.exists() {
            debug!("PIN retries entry does not exist, returning default state");
            return Ok(SerializablePinRetries::default());
        }

        let encrypted_data = std::fs::read(&path).map_err(|e| {
            warn!("Failed to read PIN retries entry: {}", e);
            soft_fido2::StatusCode::Other
        })?;

        let mut context = self.create_crypto_context().map_err(|e| {
            warn!("Failed to create crypto context: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        let ciphertext = Ciphertext::from(encrypted_data);
        let plaintext = context.decrypt(ciphertext).map_err(|e| {
            warn!("Failed to decrypt PIN retries: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        SerializablePinRetries::from_json_bytes(plaintext.unsecure_ref()).map_err(|e| {
            warn!("Failed to parse PIN retries: {:?}", e);
            soft_fido2::StatusCode::InvalidParameter
        })
    }

    fn save_config(
        &self,
        config: &SerializablePinConfig,
    ) -> std::result::Result<(), soft_fido2::StatusCode> {
        debug!("Saving PIN config to pass store");

        let bytes = config.to_json_bytes()?;

        let recipients = self.load_recipients_from_gpg_id().map_err(|e| {
            warn!("Failed to load GPG recipients: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        let mut context = self.create_crypto_context().map_err(|e| {
            warn!("Failed to create crypto context: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        let path = self.get_config_path();

        if let Some(parent) = path.parent() {
            create_secure_dir_all(parent).map_err(|e| {
                warn!("Failed to create directory: {}", e);
                soft_fido2::StatusCode::Other
            })?;
        }

        let plaintext = Plaintext::from(bytes);
        context
            .encrypt_file(&recipients, plaintext, &path)
            .map_err(|e| {
                warn!("Failed to encrypt PIN config: {:?}", e);
                soft_fido2::StatusCode::Other
            })?;

        let relative_path = path
            .strip_prefix(&self.store_path)
            .unwrap_or(&path)
            .display();
        let commit_message = format!("Update PIN configuration: {}.", relative_path);
        self.sync_finalize(&commit_message).map_err(|e| {
            warn!("Failed to sync PIN config: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        *self.last_config.write().map_err(|e| {
            warn!("Failed to acquire config lock: {:?}", e);
            soft_fido2::StatusCode::Other
        })? = Some(config.clone());
        debug!("PIN config saved and synced successfully");
        Ok(())
    }

    fn save_retries(
        &self,
        retries: &SerializablePinRetries,
    ) -> std::result::Result<(), soft_fido2::StatusCode> {
        debug!("Saving PIN retries to pass store (local only, no sync)");

        let bytes = retries.to_json_bytes()?;

        let recipients = self.load_recipients_from_gpg_id().map_err(|e| {
            warn!("Failed to load GPG recipients: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        let mut context = self.create_crypto_context().map_err(|e| {
            warn!("Failed to create crypto context: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        let path = self.get_retries_path();

        if let Some(parent) = path.parent() {
            create_secure_dir_all(parent).map_err(|e| {
                warn!("Failed to create directory: {}", e);
                soft_fido2::StatusCode::Other
            })?;
        }

        let plaintext = Plaintext::from(bytes);
        context
            .encrypt_file(&recipients, plaintext, &path)
            .map_err(|e| {
                warn!("Failed to encrypt PIN retries: {:?}", e);
                soft_fido2::StatusCode::Other
            })?;

        debug!("PIN retries saved successfully (no git sync)");
        Ok(())
    }

    fn config_changed(&self, new_config: &SerializablePinConfig) -> bool {
        let last = match self.last_config.read() {
            Ok(l) => l,
            Err(_) => return true,
        };
        match last.as_ref() {
            Some(old) => old != new_config,
            None => true,
        }
    }

    /// Check for conflict between local changes and remote config
    /// Returns Some(resolved_config) if conflict was resolved, None if no conflict
    fn check_and_resolve_conflict(
        &self,
        local_config: &SerializablePinConfig,
    ) -> std::result::Result<Option<SerializablePinConfig>, soft_fido2::StatusCode> {
        let last_synced = match self.last_synced.read() {
            Ok(l) => l.clone(),
            Err(_) => return Ok(None),
        };

        let Some(synced) = last_synced else {
            debug!("No previous synced state, no conflict check needed");
            return Ok(None);
        };

        // Pull latest from remote to check for conflicts
        if let Err(e) = self.sync_prepare() {
            warn!("Failed to prepare sync for conflict check: {:?}", e);
        }

        // Load remote config after pull
        let remote_config = self.load_config()?;

        // Check if remote changed since we last synced
        let remote_changed =
            remote_config.version != synced.version || remote_config.pin_hash != synced.pin_hash;

        if !remote_changed {
            debug!("Remote config unchanged since last sync, no conflict");
            return Ok(None);
        }

        // Check if local changed since we last synced
        let local_changed =
            local_config.version != synced.version || local_config.pin_hash != synced.pin_hash;

        if !local_changed {
            debug!("Remote changed but local unchanged, using remote config");
            return Ok(Some(remote_config));
        }

        // Both changed - conflict detected
        warn!("PIN config conflict detected: both local and remote changed since last sync");
        warn!(
            "Local: version={}, modified_at={:?}",
            local_config.version, local_config.modified_at
        );
        warn!(
            "Remote: version={}, modified_at={:?}",
            remote_config.version, remote_config.modified_at
        );

        // Timestamp-based resolution: newer wins
        let local_time = local_config.modified_at.unwrap_or(0);
        let remote_time = remote_config.modified_at.unwrap_or(0);

        if remote_time > local_time {
            info!(
                "Conflict resolved: remote config is newer ({} > {}), using remote",
                remote_time, local_time
            );
            return Ok(Some(remote_config));
        } else if local_time > remote_time {
            info!(
                "Conflict resolved: local config is newer ({} > {}), keeping local",
                local_time, remote_time
            );
            return Ok(None);
        }

        // Same timestamp or both missing - use version as tie-breaker
        if remote_config.version > local_config.version {
            info!(
                "Conflict resolved: remote has higher version ({} > {})",
                remote_config.version, local_config.version
            );
            return Ok(Some(remote_config));
        }

        info!(
            "Conflict resolved: local has higher or equal version ({} >= {})",
            local_config.version, remote_config.version
        );
        Ok(None)
    }
}

impl PinStorage for PassPinStorage {
    fn load_pin_state(&self) -> std::result::Result<soft_fido2::PinState, soft_fido2::StatusCode> {
        // Pull latest changes from git remote if configured
        if let Err(e) = self.sync_prepare() {
            warn!("Failed to prepare sync for PIN config: {:?}", e);
        }

        let config = self.load_config()?;
        let retries = self.load_retries()?;

        // Track synced state for conflict detection
        *self.last_synced.write().map_err(|e| {
            warn!("Failed to acquire synced lock: {:?}", e);
            soft_fido2::StatusCode::Other
        })? = Some(SyncedConfig {
            version: config.version,
            modified_at: config.modified_at,
            pin_hash: config.pin_hash.clone(),
        });

        *self.last_config.write().map_err(|e| {
            warn!("Failed to acquire config lock: {:?}", e);
            soft_fido2::StatusCode::Other
        })? = Some(config.clone());

        let state = SerializablePinState::from_parts(&config, &retries);
        Ok(state.into())
    }

    fn save_pin_state(
        &self,
        state: &soft_fido2::PinState,
    ) -> std::result::Result<(), soft_fido2::StatusCode> {
        let new_config = SerializablePinConfig::from(state);
        let new_retries = SerializablePinRetries::from(state);

        if state.is_pin_set() {
            info!(
                "Saving PIN state (PIN is set, {} retries remaining)",
                state.retries
            );
        } else {
            info!("Saving PIN state (no PIN set)");
        }

        if self.config_changed(&new_config) {
            debug!("PIN config changed, checking for conflicts...");

            // Check for conflicts with remote
            match self.check_and_resolve_conflict(&new_config)? {
                Some(resolved_config) => {
                    warn!("Conflict resolved by using remote config, updating local state");
                    // Use resolved config from remote, but update retries locally
                    let resolved_state =
                        SerializablePinState::from_parts(&resolved_config, &new_retries);
                    let _resolved_pin_state: soft_fido2::PinState = resolved_state.into();

                    // Update our tracked state
                    *self.last_synced.write().map_err(|e| {
                        warn!("Failed to acquire synced lock: {:?}", e);
                        soft_fido2::StatusCode::Other
                    })? = Some(SyncedConfig {
                        version: resolved_config.version,
                        modified_at: resolved_config.modified_at,
                        pin_hash: resolved_config.pin_hash.clone(),
                    });

                    *self.last_config.write().map_err(|e| {
                        warn!("Failed to acquire config lock: {:?}", e);
                        soft_fido2::StatusCode::Other
                    })? = Some(resolved_config);

                    // Save retries locally (no sync)
                    self.save_retries(&new_retries)?;

                    // Return error to indicate the operation should be retried with updated state
                    return Err(soft_fido2::StatusCode::Other);
                }
                None => {
                    debug!("No conflict, proceeding with save");
                }
            }

            debug!("Saving PIN config and syncing");
            self.save_config(&new_config)?;

            // Update synced state after successful save
            *self.last_synced.write().map_err(|e| {
                warn!("Failed to acquire synced lock: {:?}", e);
                soft_fido2::StatusCode::Other
            })? = Some(SyncedConfig {
                version: new_config.version,
                modified_at: new_config.modified_at,
                pin_hash: new_config.pin_hash.clone(),
            });
        } else {
            debug!("PIN config unchanged, skipping save");
        }

        self.save_retries(&new_retries)?;

        Ok(())
    }
}
