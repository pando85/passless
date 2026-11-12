//! The persistent granted-rules store (ADR 0014 section 8.4).
//!
//! An approved escalation persists an exact `authenticate = allow` entry for one RP. Resolution
//! consults it only to upgrade a configured `request` ([`GrantSource`]), so an entry whose rule
//! was removed or set to `deny` is inert.
//!
//! One TOML file per profile, `<state_dir>/granted-rules/<profile>.toml`, owned by the daemon user
//! with mode 0600 in a 0700 directory. Writes are atomic (temporary file, fsync, rename, fsync of
//! the directory) and serialized per profile. The store directory is opened once as a pinned handle
//! (`safe_fs::Dir`: `O_NOFOLLOW`, then owner and mode on the descriptor) and the temporary file, the
//! rename, the fsync and the reload all go through it, so a symlink planted in its place is refused
//! and a path swap cannot redirect a write (final security review L4). Every load is fail-closed: a file that is not a
//! regular file owned by the daemon with mode 0600 or less, is too large, does not parse, has an
//! unknown version, or holds an invalid or duplicate entry disables grants for that profile
//! ([`ProfileGrants::Disabled`]). A disabled profile is never written, so a damaged file is left
//! for the operator to inspect.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use passless_core::agent::{CredentialRef, GrantSource, ProfileId, validate_rp_id};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::lock_order::{self, LockLevel};
use super::policy_engine::PolicyRuntime;
use super::safe_fs::Dir;

/// The only store format version.
pub const GRANTED_RULES_VERSION: u32 = 1;
/// Largest store file that is loaded; a larger one disables the profile's grants.
pub const MAX_STORE_FILE_BYTES: u64 = 256 * 1024;
/// The store's directory under `agents.state_dir`.
pub const GRANTED_RULES_DIR: &str = "granted-rules";

/// The action a granted rule allows. Only `authenticate` is ever granted: registration is the
/// explicit `register = "allow"` setting (ADR 0014 section 8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantedAction {
    Authenticate,
}

impl GrantedAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authenticate => "authenticate",
        }
    }
}

/// How a granted rule came to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    /// An approved `authenticate` escalation.
    Escalation,
    /// A credential created after an approved registration escalation; carries its reference.
    Registration,
}

impl GrantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Escalation => "escalation",
            Self::Registration => "registration",
        }
    }
}

/// The configured rule that permitted the escalation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PermittingRule {
    /// The exact rule for the RP.
    #[serde(rename = "exact")]
    Exact,
    /// The constrained `*` rule.
    #[serde(rename = "*")]
    Wildcard,
}

impl PermittingRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Wildcard => "*",
        }
    }
}

/// One granted rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantedRule {
    /// The exact RP ID, normalized by `validate_rp_id`.
    pub rp_id: String,
    pub action: GrantedAction,
    pub kind: GrantKind,
    /// RFC 3339 UTC time of the approval.
    pub granted_at: String,
    /// The approving escalation's ID.
    pub request_id: String,
    /// The origin of the ceremony that requested the escalation.
    pub origin: String,
    pub rule: PermittingRule,
    /// The credential a registration grant pins (ADR 0014 section 8.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<CredentialRef>,
}

impl GrantedRule {
    /// An `authenticate` grant approved now.
    pub fn new(
        rp_id: &str,
        kind: GrantKind,
        request_id: &str,
        origin: &str,
        rule: PermittingRule,
        credential_ref: Option<CredentialRef>,
    ) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            action: GrantedAction::Authenticate,
            kind,
            granted_at: rfc3339_utc(SystemTime::now()),
            request_id: request_id.to_string(),
            origin: origin.to_string(),
            rule,
            credential_ref,
        }
    }

    /// Two entries with the same key are duplicates. A registration grant per credential may sit
    /// next to the RP's escalation grant.
    fn key(&self) -> (String, GrantedAction, Option<String>) {
        (
            self.rp_id.clone(),
            self.action,
            self.credential_ref.as_ref().map(CredentialRef::to_hex),
        )
    }
}

/// The file format.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    version: u32,
    profile: String,
    #[serde(default, rename = "grant")]
    grants: Vec<GrantedRule>,
}

/// The loaded state of one profile's store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileGrants {
    /// The store loaded (an absent file is an empty store).
    Enabled(Vec<GrantedRule>),
    /// The store failed a load check: grants are off for the profile until the operator fixes
    /// or removes the file and restarts the daemon (fail closed).
    Disabled(String),
}

impl ProfileGrants {
    pub fn rules(&self) -> &[GrantedRule] {
        match self {
            Self::Enabled(rules) => rules,
            Self::Disabled(_) => &[],
        }
    }

    pub fn disabled_reason(&self) -> Option<&str> {
        match self {
            Self::Enabled(_) => None,
            Self::Disabled(reason) => Some(reason),
        }
    }
}

/// Why a store operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantStoreError {
    UnknownProfile(String),
    /// The profile's store is disabled (escalation is denied with `grants_unavailable`).
    Unavailable(String),
    /// The profile holds `max_granted_rules` entries already.
    CapReached(usize),
    /// The profile holds `max_wildcard_registrations` wildcard registration grants already
    /// (ADR 0014 amendment section 2.2 item 4).
    WildcardCapReached(usize),
    InvalidRpId(String),
    /// No matching granted rule.
    NotFound,
    /// Writing the store failed; nothing changed.
    Io(String),
    /// The RP's grants were revoked (or the profile's cleared) after the escalation captured its
    /// [`RevokeToken`]: the late approval persists nothing (review M-c, M-d).
    Revoked,
}

impl fmt::Display for GrantStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProfile(profile) => write!(f, "unknown agent profile '{}'", profile),
            Self::Unavailable(reason) => write!(f, "granted rules are unavailable: {}", reason),
            Self::CapReached(max) => {
                write!(f, "the profile already holds max_granted_rules ({})", max)
            }
            Self::WildcardCapReached(max) => write!(
                f,
                "the profile already holds max_wildcard_registrations ({}) wildcard registration grants",
                max
            ),
            Self::InvalidRpId(e) => write!(f, "invalid RP ID: {}", e),
            Self::NotFound => write!(f, "no matching granted rule"),
            Self::Io(e) => write!(f, "granted-rules store write failed: {}", e),
            Self::Revoked => write!(
                f,
                "the RP's granted rules were revoked after this escalation was raised"
            ),
        }
    }
}

impl std::error::Error for GrantStoreError {}

/// What an add did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    /// The rule was persisted; carries the new grant epoch.
    Added { grant_epoch: u64 },
    /// An identical entry already existed; nothing was written.
    AlreadyGranted,
}

/// What a revoke or clear did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeOutcome {
    /// Entries removed.
    pub revoked: usize,
    /// The revocation epoch now in force (unchanged when nothing was removed).
    pub revocation_epoch: u64,
}

/// The revocation generations of one `(profile, RP)`, captured when an escalation is raised
/// ([`GrantedRulesStore::revoke_token`]) and checked when its approval persists a grant
/// ([`GrantedRulesStore::add_unless_revoked`]). `grants revoke` bumps the RP's generation and
/// `grants clear` the profile's, both under the profile's writer, so an approval in flight across a
/// revocation persists nothing whatever the interleaving with the escalation cancel that follows
/// it (review M-c, M-d).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeToken {
    profile: u64,
    rp: u64,
}

/// What a profile's writer guards besides the file: its revocation generations.
#[derive(Debug, Default)]
struct WriterState {
    profile_generation: u64,
    rp_generations: HashMap<String, u64>,
}

#[cfg(test)]
impl RevokeToken {
    pub fn for_test(profile: u64, rp: u64) -> Self {
        Self { profile, rp }
    }
}

impl WriterState {
    fn token(&self, normalized_rp: &str) -> RevokeToken {
        RevokeToken {
            profile: self.profile_generation,
            rp: self.rp_generations.get(normalized_rp).copied().unwrap_or(0),
        }
    }
}

/// The granted-rules store of every configured profile.
pub struct GrantedRulesStore {
    /// `<state_dir>/granted-rules`.
    dir: PathBuf,
    /// The UID that must own the store (the daemon's euid).
    owner_uid: u32,
    /// The loaded view per profile, swapped after every write (`LockLevel::GrantedRulesView`).
    views: RwLock<HashMap<ProfileId, Arc<ProfileGrants>>>,
    /// Per-profile write mutex (`LockLevel::GrantedRulesFile`): held across the file write, the
    /// reload and the view swap, released before any epoch bump. The profile set is fixed at
    /// startup (adding a profile needs a restart). It also guards the revocation generations.
    writers: HashMap<ProfileId, Mutex<WriterState>>,
}

impl fmt::Debug for GrantedRulesStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantedRulesStore")
            .field("dir", &self.dir)
            .field("owner_uid", &self.owner_uid)
            .finish_non_exhaustive()
    }
}

impl GrantedRulesStore {
    /// Load the store of every profile under `state_dir`, owned by the daemon's euid.
    pub fn open(state_dir: &Path, profiles: impl IntoIterator<Item = ProfileId>) -> Self {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        Self::open_with_owner(state_dir, profiles, euid)
    }

    /// Like [`Self::open`] with an explicit owner UID.
    pub fn open_with_owner(
        state_dir: &Path,
        profiles: impl IntoIterator<Item = ProfileId>,
        owner_uid: u32,
    ) -> Self {
        let dir = state_dir.join(GRANTED_RULES_DIR);
        let mut views = HashMap::new();
        let mut writers = HashMap::new();
        for profile in profiles {
            let loaded = load_profile(&dir, &profile, owner_uid);
            if let ProfileGrants::Disabled(reason) = &loaded {
                log::warn!(
                    "agent profile '{}': granted rules disabled: {}",
                    profile,
                    reason
                );
            }
            views.insert(profile.clone(), Arc::new(loaded));
            writers.insert(profile, Mutex::new(WriterState::default()));
        }
        Self {
            dir,
            owner_uid,
            views: RwLock::new(views),
            writers,
        }
    }

    /// A store whose every profile is disabled with `reason` (no usable state directory).
    pub fn disabled(profiles: impl IntoIterator<Item = ProfileId>, reason: &str) -> Self {
        let mut views = HashMap::new();
        let mut writers = HashMap::new();
        for profile in profiles {
            log::warn!(
                "agent profile '{}': granted rules disabled: {}",
                profile,
                reason
            );
            views.insert(
                profile.clone(),
                Arc::new(ProfileGrants::Disabled(reason.to_string())),
            );
            writers.insert(profile, Mutex::new(WriterState::default()));
        }
        Self {
            dir: PathBuf::new(),
            // SAFETY: geteuid has no preconditions and cannot fail.
            owner_uid: unsafe { libc::geteuid() },
            views: RwLock::new(views),
            writers,
        }
    }

    /// The store directory (`<state_dir>/granted-rules`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The store file of `profile`.
    pub fn path_for(&self, profile: &ProfileId) -> PathBuf {
        store_path(&self.dir, profile)
    }

    /// The loaded view of `profile`.
    pub fn profile(&self, profile: &ProfileId) -> Option<Arc<ProfileGrants>> {
        lock_order::read(&self.views, LockLevel::GrantedRulesView)
            .get(profile)
            .cloned()
    }

    /// Every profile's view, sorted by profile.
    pub fn list(&self) -> Vec<(ProfileId, Arc<ProfileGrants>)> {
        let mut all: Vec<_> = lock_order::read(&self.views, LockLevel::GrantedRulesView)
            .iter()
            .map(|(profile, view)| (profile.clone(), Arc::clone(view)))
            .collect();
        all.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        all
    }

    /// Persist `rule` for `profile`, then bump the grant epoch (additive: no session is revoked).
    ///
    /// Refused when the profile's store is disabled, when it holds `max_rules` entries, or when the
    /// RP ID is not a valid, normalized exact RP ID. An identical entry is not written twice.
    pub fn add(
        &self,
        policy: &PolicyRuntime,
        profile: &ProfileId,
        rule: GrantedRule,
        max_rules: usize,
    ) -> Result<AddOutcome, GrantStoreError> {
        self.add_unless_revoked(policy, profile, rule, max_rules, None)
    }

    /// The current [`RevokeToken`] of `rp_id` in `profile`.
    pub fn revoke_token(
        &self,
        profile: &ProfileId,
        rp_id: &str,
    ) -> Result<RevokeToken, GrantStoreError> {
        let normalized =
            validate_rp_id(rp_id).map_err(|e| GrantStoreError::InvalidRpId(e.to_string()))?;
        Ok(self.lock_writer(profile)?.token(&normalized))
    }

    /// [`Self::add`], refused with [`GrantStoreError::Revoked`] when `token` is given and the
    /// rule's RP was revoked or the profile cleared since it was captured. The check and the write
    /// happen under the same writer as the revocations, so they are atomic with respect to them.
    pub fn add_unless_revoked(
        &self,
        policy: &PolicyRuntime,
        profile: &ProfileId,
        rule: GrantedRule,
        max_rules: usize,
        token: Option<RevokeToken>,
    ) -> Result<AddOutcome, GrantStoreError> {
        self.add_with_wildcard_cap(policy, profile, rule, max_rules, token, None)
    }

    /// [`Self::add_unless_revoked`], also refused with [`GrantStoreError::WildcardCapReached`]
    /// when `wildcard_cap` is given and the profile already holds that many wildcard registration
    /// grants ([`wildcard_registration_count`]), checked under the same writer as the write.
    pub fn add_with_wildcard_cap(
        &self,
        policy: &PolicyRuntime,
        profile: &ProfileId,
        mut rule: GrantedRule,
        max_rules: usize,
        token: Option<RevokeToken>,
        wildcard_cap: Option<usize>,
    ) -> Result<AddOutcome, GrantStoreError> {
        let normalized =
            validate_rp_id(&rule.rp_id).map_err(|e| GrantStoreError::InvalidRpId(e.to_string()))?;
        if normalized == passless_core::agent::config::ANY_RP_ID {
            return Err(GrantStoreError::InvalidRpId(
                "a granted rule names one exact RP".to_string(),
            ));
        }
        rule.rp_id = normalized;
        {
            let writer = self.lock_writer(profile)?;
            if token.is_some_and(|token| token != writer.token(&rule.rp_id)) {
                return Err(GrantStoreError::Revoked);
            }
            let mut rules = self.enabled_rules(profile)?;
            if rules.iter().any(|existing| existing.key() == rule.key()) {
                return Ok(AddOutcome::AlreadyGranted);
            }
            if rules.len() >= max_rules {
                return Err(GrantStoreError::CapReached(max_rules));
            }
            if let Some(cap) = wildcard_cap
                && wildcard_registration_count(&rules) >= cap
            {
                return Err(GrantStoreError::WildcardCapReached(cap));
            }
            rules.push(rule);
            self.persist_and_swap(profile, rules)?;
        }
        Ok(AddOutcome::Added {
            grant_epoch: policy.bump_grant_epoch(),
        })
    }

    /// Remove the granted rules of `rp_id` and `action` (every credential's registration grant
    /// too), then bump the revocation epoch. The caller revokes the stale sessions.
    pub fn revoke(
        &self,
        policy: &PolicyRuntime,
        profile: &ProfileId,
        rp_id: &str,
        action: GrantedAction,
    ) -> Result<RevokeOutcome, GrantStoreError> {
        let normalized =
            validate_rp_id(rp_id).map_err(|e| GrantStoreError::InvalidRpId(e.to_string()))?;
        let revoked = {
            let mut writer = self.lock_writer(profile)?;
            // Bumped first, also when nothing is stored: an approval between its escalation and
            // its store write must not persist what the operator just revoked.
            *writer.rp_generations.entry(normalized.clone()).or_default() += 1;
            let rules = self.enabled_rules(profile)?;
            let before = rules.len();
            let kept: Vec<_> = rules
                .into_iter()
                .filter(|rule| !(rule.rp_id == normalized && rule.action == action))
                .collect();
            let revoked = before - kept.len();
            if revoked == 0 {
                return Err(GrantStoreError::NotFound);
            }
            self.persist_and_swap(profile, kept)?;
            revoked
        };
        Ok(RevokeOutcome {
            revoked,
            revocation_epoch: policy.bump_revocation_epoch(),
        })
    }

    /// Remove the granted rules the escalation `request_id` persisted, then bump the revocation
    /// epoch. This is the compensation of an approval that a reload or a clear overtook while the
    /// grant was being written (ADR 0014 section 8): it never touches another escalation's grant.
    /// [`GrantStoreError::NotFound`] when this escalation persisted nothing.
    pub fn revoke_request(
        &self,
        policy: &PolicyRuntime,
        profile: &ProfileId,
        request_id: &str,
    ) -> Result<RevokeOutcome, GrantStoreError> {
        let revoked = {
            let _writer = self.lock_writer(profile)?;
            let rules = self.enabled_rules(profile)?;
            let before = rules.len();
            let kept: Vec<_> = rules
                .into_iter()
                .filter(|rule| rule.request_id != request_id)
                .collect();
            let revoked = before - kept.len();
            if revoked == 0 {
                return Err(GrantStoreError::NotFound);
            }
            self.persist_and_swap(profile, kept)?;
            revoked
        };
        Ok(RevokeOutcome {
            revoked,
            revocation_epoch: policy.bump_revocation_epoch(),
        })
    }

    /// Remove every granted rule of `profile`, then bump the revocation epoch when anything was
    /// removed. The caller revokes the stale sessions.
    pub fn clear(
        &self,
        policy: &PolicyRuntime,
        profile: &ProfileId,
    ) -> Result<RevokeOutcome, GrantStoreError> {
        let revoked = {
            let mut writer = self.lock_writer(profile)?;
            writer.profile_generation += 1;
            let rules = self.enabled_rules(profile)?;
            if !rules.is_empty() {
                self.persist_and_swap(profile, Vec::new())?;
            }
            rules.len()
        };
        let revocation_epoch = if revoked > 0 {
            policy.bump_revocation_epoch()
        } else {
            policy.revocation_epoch()
        };
        Ok(RevokeOutcome {
            revoked,
            revocation_epoch,
        })
    }

    /// A digest of `profile`'s granted rules, reported next to the policy digest. It is separate
    /// from the policy digest, so a reload's no-op comparison covers configuration only.
    pub fn grants_digest(&self, profile: &ProfileId) -> Option<String> {
        self.profile(profile)
            .map(|view| digest_of(profile, view.as_ref()))
    }

    fn lock_writer(
        &self,
        profile: &ProfileId,
    ) -> Result<lock_order::Tracked<std::sync::MutexGuard<'_, WriterState>>, GrantStoreError> {
        let writer = self
            .writers
            .get(profile)
            .ok_or_else(|| GrantStoreError::UnknownProfile(profile.to_string()))?;
        Ok(lock_order::lock(writer, LockLevel::GrantedRulesFile))
    }

    fn enabled_rules(&self, profile: &ProfileId) -> Result<Vec<GrantedRule>, GrantStoreError> {
        match self.profile(profile).as_deref() {
            Some(ProfileGrants::Enabled(rules)) => Ok(rules.clone()),
            Some(ProfileGrants::Disabled(reason)) => {
                Err(GrantStoreError::Unavailable(reason.clone()))
            }
            None => Err(GrantStoreError::UnknownProfile(profile.to_string())),
        }
    }

    /// Write `rules`, reload the file through the load checks and publish what loaded. Called with
    /// the profile's writer held.
    fn persist_and_swap(
        &self,
        profile: &ProfileId,
        mut rules: Vec<GrantedRule>,
    ) -> Result<(), GrantStoreError> {
        rules.sort_by_key(GrantedRule::key);
        let file = StoreFile {
            version: GRANTED_RULES_VERSION,
            profile: profile.as_str().to_string(),
            grants: rules,
        };
        let content = toml::to_string(&file).map_err(|e| GrantStoreError::Io(e.to_string()))?;
        // One pinned directory handle for the write and the reload that checks it.
        let handle = open_store_dir(&self.dir, true, self.owner_uid)
            .map_err(GrantStoreError::Io)?
            .ok_or_else(|| {
                GrantStoreError::Io("the store directory could not be created".to_string())
            })?;
        write_in(&handle, profile, content.as_bytes())
            .map_err(|e| GrantStoreError::Io(e.to_string()))?;
        let loaded = load_profile_from(&handle, &self.dir, profile, self.owner_uid);
        let result = match &loaded {
            ProfileGrants::Enabled(_) => Ok(()),
            ProfileGrants::Disabled(reason) => Err(GrantStoreError::Unavailable(reason.clone())),
        };
        lock_order::write(&self.views, LockLevel::GrantedRulesView)
            .insert(profile.clone(), Arc::new(loaded));
        result
    }
}

impl GrantSource for GrantedRulesStore {
    fn is_granted(&self, profile_id: &ProfileId, rp_id: &str) -> bool {
        let Ok(normalized) = validate_rp_id(rp_id) else {
            return false;
        };
        self.profile(profile_id).is_some_and(|view| {
            view.rules()
                .iter()
                .any(|rule| rule.rp_id == normalized && rule.action == GrantedAction::Authenticate)
        })
    }

    fn granted_credential_refs(&self, profile_id: &ProfileId, rp_id: &str) -> Vec<CredentialRef> {
        let Ok(normalized) = validate_rp_id(rp_id) else {
            return Vec::new();
        };
        let Some(view) = self.profile(profile_id) else {
            return Vec::new();
        };
        view.rules()
            .iter()
            .filter(|rule| rule.rp_id == normalized && rule.action == GrantedAction::Authenticate)
            .filter_map(|rule| rule.credential_ref.clone())
            .collect()
    }
}

/// How many of `rules` are wildcard registration grants: `kind = "registration"` with
/// `rule = "*"`. This is what `max_wildcard_registrations` caps (ADR 0014 amendment section 2.2
/// item 4); revoking such a grant frees a slot.
pub fn wildcard_registration_count(rules: &[GrantedRule]) -> usize {
    rules
        .iter()
        .filter(|rule| {
            rule.kind == GrantKind::Registration && rule.rule == PermittingRule::Wildcard
        })
        .count()
}

fn store_path(dir: &Path, profile: &ProfileId) -> PathBuf {
    dir.join(format!("{}.toml", profile.as_str()))
}

fn store_name(profile: &ProfileId) -> String {
    format!("{}.toml", profile.as_str())
}

fn tmp_name(profile: &ProfileId) -> String {
    format!(".{}.toml.tmp", profile.as_str())
}

/// Load one profile's store with every fail-closed check (module docs).
fn load_profile(dir: &Path, profile: &ProfileId, owner_uid: u32) -> ProfileGrants {
    match open_store_dir(dir, false, owner_uid) {
        Err(reason) => ProfileGrants::Disabled(reason),
        Ok(None) => ProfileGrants::Enabled(Vec::new()),
        Ok(Some(handle)) => load_profile_from(&handle, dir, profile, owner_uid),
    }
}

/// [`load_profile`] through an already pinned store directory `handle` (`dir` is its path, for
/// messages only): the file is opened relative to the descriptor with `O_NOFOLLOW`, so the path
/// cannot be redirected between the directory check and the read.
fn load_profile_from(
    handle: &Dir,
    dir: &Path,
    profile: &ProfileId,
    owner_uid: u32,
) -> ProfileGrants {
    let path = store_path(dir, profile);
    let mut file = match handle.open_nofollow(&store_name(profile)) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return ProfileGrants::Enabled(Vec::new());
        }
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return ProfileGrants::Disabled(format!("{} is a symlink", path.display()));
        }
        Err(e) => {
            return ProfileGrants::Disabled(format!("cannot open {}: {}", path.display(), e));
        }
    };
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(e) => {
            return ProfileGrants::Disabled(format!("cannot stat {}: {}", path.display(), e));
        }
    };
    if !meta.file_type().is_file() {
        return ProfileGrants::Disabled(format!("{} is not a regular file", path.display()));
    }
    if meta.uid() != owner_uid {
        return ProfileGrants::Disabled(format!(
            "{} is owned by uid {}, not the daemon's uid {}",
            path.display(),
            meta.uid(),
            owner_uid
        ));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return ProfileGrants::Disabled(format!(
            "{} has mode {:04o}; it must not be accessible to group or others (0600)",
            path.display(),
            mode
        ));
    }
    if meta.len() > MAX_STORE_FILE_BYTES {
        return ProfileGrants::Disabled(format!(
            "{} is larger than {} bytes",
            path.display(),
            MAX_STORE_FILE_BYTES
        ));
    }
    let mut content = Vec::new();
    if let Err(e) = (&mut file)
        .take(MAX_STORE_FILE_BYTES + 1)
        .read_to_end(&mut content)
    {
        return ProfileGrants::Disabled(format!("cannot read {}: {}", path.display(), e));
    }
    if content.len() as u64 > MAX_STORE_FILE_BYTES {
        return ProfileGrants::Disabled(format!(
            "{} is larger than {} bytes",
            path.display(),
            MAX_STORE_FILE_BYTES
        ));
    }
    match parse_store(&content, profile) {
        Ok(rules) => ProfileGrants::Enabled(rules),
        Err(reason) => ProfileGrants::Disabled(format!("{}: {}", path.display(), reason)),
    }
}

/// Open the store directory `dir` (`<state_dir>/granted-rules`) as a pinned handle (review L4).
///
/// Everything after this call goes through the descriptor: the directory is opened with
/// `openat(O_DIRECTORY | O_NOFOLLOW)` below its parent, so a symlink planted in its place is
/// refused, and the owner and mode checks are `fstat` on the descriptor that is then used for the
/// temporary file, the rename and the fsync, so a later swap of the path cannot redirect them.
/// Missing is `Ok(None)` unless `create` (the directory is then made 0700). The state directory
/// (the parent) is the operator's: it is resolved once and may itself be, or live under, a
/// symlink; the store directory below it never may.
fn open_store_dir(dir: &Path, create: bool, owner_uid: u32) -> Result<Option<Dir>, String> {
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name().and_then(|n| n.to_str()))
    else {
        return Err(format!("{} is not a usable store directory", dir.display()));
    };
    if create {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    let parent = match fs::canonicalize(parent) {
        Ok(parent) => parent,
        Err(e) if e.kind() == io::ErrorKind::NotFound && !create => return Ok(None),
        Err(e) => return Err(format!("cannot resolve {}: {}", parent.display(), e)),
    };
    let parent_dir =
        Dir::open_path(&parent).map_err(|e| format!("cannot open {}: {}", parent.display(), e))?;
    let not_followed = |e: &io::Error| {
        // `O_NOFOLLOW | O_DIRECTORY` on a symlink reports ELOOP or ENOTDIR, depending on the kernel
        // path; a plain file in its place is ENOTDIR too.
        matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR))
    };
    let handle = match parent_dir.open_dir(name) {
        Ok(handle) => handle,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if !create {
                return Ok(None);
            }
            match parent_dir.create_dir(name, 0o700) {
                Ok(handle) => handle,
                // Created by a concurrent opener meanwhile: use it, after the checks below.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => parent_dir
                    .open_dir(name)
                    .map_err(|e| format!("cannot open {}: {}", dir.display(), e))?,
                Err(e) => return Err(format!("cannot create {}: {}", dir.display(), e)),
            }
        }
        Err(e) if not_followed(&e) => {
            return Err(format!("{} is a symlink or not a directory", dir.display()));
        }
        Err(e) => return Err(format!("cannot open {}: {}", dir.display(), e)),
    };
    check_dir_handle(&handle, dir, owner_uid)?;
    Ok(Some(handle))
}

/// The store directory must be owned by the daemon and not accessible to group or others.
fn check_dir_handle(handle: &Dir, dir: &Path, owner_uid: u32) -> Result<(), String> {
    let st = handle
        .stat()
        .map_err(|e| format!("cannot stat {}: {}", dir.display(), e))?;
    if st.st_uid != owner_uid {
        return Err(format!(
            "{} is owned by uid {}, not the daemon's uid {}",
            dir.display(),
            st.st_uid,
            owner_uid
        ));
    }
    if st.st_mode & 0o077 != 0 {
        return Err(format!(
            "{} has mode {:04o}; it must not be accessible to group or others (0700)",
            dir.display(),
            st.st_mode & 0o7777
        ));
    }
    Ok(())
}

fn parse_store(content: &[u8], profile: &ProfileId) -> Result<Vec<GrantedRule>, String> {
    let text = std::str::from_utf8(content).map_err(|_| "not UTF-8".to_string())?;
    let file: StoreFile = toml::from_str(text).map_err(|e| format!("does not parse: {}", e))?;
    if file.version != GRANTED_RULES_VERSION {
        return Err(format!("unknown version {}", file.version));
    }
    if file.profile != profile.as_str() {
        return Err(format!(
            "belongs to profile '{}', not '{}'",
            file.profile, profile
        ));
    }
    let mut seen = BTreeSet::new();
    for rule in &file.grants {
        match validate_rp_id(&rule.rp_id) {
            Ok(normalized)
                if normalized == rule.rp_id
                    && normalized != passless_core::agent::config::ANY_RP_ID => {}
            Ok(_) => {
                return Err(format!(
                    "rp_id '{}' is not a normalized exact RP ID",
                    rule.rp_id
                ));
            }
            Err(e) => return Err(format!("invalid rp_id '{}': {}", rule.rp_id, e)),
        }
        if rule.kind == GrantKind::Registration && rule.credential_ref.is_none() {
            return Err(format!(
                "registration grant for '{}' has no credential_ref",
                rule.rp_id
            ));
        }
        if !seen.insert(rule.key()) {
            return Err(format!("duplicate entry for '{}'", rule.rp_id));
        }
    }
    Ok(file.grants)
}

/// Write `content` as the profile's store (review L4): open the store directory as a pinned handle
/// (created 0700), then see [`write_in`]. The store itself opens the handle once for the write and
/// the reload ([`GrantedRulesStore::persist_and_swap`]); this is the one-shot form the tests use.
#[cfg(test)]
fn write_atomically(
    dir: &Path,
    profile: &ProfileId,
    content: &[u8],
    owner_uid: u32,
) -> io::Result<()> {
    let handle = open_store_dir(dir, true, owner_uid)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("the store directory could not be created"))?;
    write_in(&handle, profile, content)
}

/// Write `content` into the pinned store directory `handle`: an exclusive 0600 temporary file
/// (`openat(O_CREAT | O_EXCL | O_NOFOLLOW)` after an `unlinkat` of any leftover, so a planted
/// symlink or file is removed, never followed), fsync, `renameat` over the store, fsync of the
/// directory.
fn write_in(handle: &Dir, profile: &ProfileId, content: &[u8]) -> io::Result<()> {
    let tmp = tmp_name(profile);
    handle.remove_file(&tmp)?;
    let result = (|| {
        let file = handle.create_file(&tmp, 0o600, content)?;
        file.sync_all()?;
        drop(file);
        handle.rename(&tmp, &store_name(profile))?;
        handle.sync()
    })();
    if result.is_err() {
        let _ = handle.remove_file(&tmp);
    }
    result
}

fn digest_of(profile: &ProfileId, view: &ProfileGrants) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"passless/granted-rules/v1\0");
    hasher.update(profile.as_str().as_bytes());
    hasher.update([0]);
    match view {
        ProfileGrants::Disabled(_) => hasher.update(b"disabled"),
        ProfileGrants::Enabled(rules) => {
            let mut sorted: Vec<&GrantedRule> = rules.iter().collect();
            sorted.sort_by_key(|rule| rule.key());
            for rule in sorted {
                for field in [
                    rule.rp_id.as_str(),
                    rule.action.as_str(),
                    rule.kind.as_str(),
                    rule.granted_at.as_str(),
                    rule.request_id.as_str(),
                    rule.origin.as_str(),
                    rule.rule.as_str(),
                    &rule
                        .credential_ref
                        .as_ref()
                        .map(CredentialRef::to_hex)
                        .unwrap_or_default(),
                ] {
                    hasher.update((field.len() as u64).to_le_bytes());
                    hasher.update(field.as_bytes());
                }
            }
        }
    }
    hex::encode(hasher.finalize())
}

/// `time` as RFC 3339 UTC with second precision (`2026-11-11T09:30:00Z`).
pub fn rfc3339_utc(time: SystemTime) -> String {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::time::{Duration, Instant};

    use passless_core::agent::protocol::GrantAction;
    use passless_core::agent::{AgentConfig, RuleAction};

    use crate::agent::browser::SystemClock;
    use crate::agent::session::{AgentSession, SessionBinding, SessionInvalid};

    const PROFILE: &str = "agent";

    fn profile() -> ProfileId {
        ProfileId::new(PROFILE).unwrap()
    }

    fn config() -> AgentConfig {
        AgentConfig::from_toml_str(
            r#"
[agents]
enabled = true
audit_path = "/nonexistent/audit"

[agents.profiles.agent]
mode = "same-user"
principal_user = "alice"

[[agents.profiles.agent.rules]]
rp_id = "example.com"
authenticate = "request"
register = "deny"

[[agents.profiles.agent.rules]]
rp_id = "other.example"
authenticate = "request"
register = "deny"
"#,
            "test",
        )
        .unwrap()
    }

    fn policy() -> PolicyRuntime {
        PolicyRuntime::new(&config(), Arc::new(SystemClock), None).unwrap()
    }

    fn own_uid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    fn open(state_dir: &Path) -> GrantedRulesStore {
        GrantedRulesStore::open(state_dir, [profile()])
    }

    fn escalation(rp_id: &str) -> GrantedRule {
        GrantedRule::new(
            rp_id,
            GrantKind::Escalation,
            "esc-1",
            &format!("https://{rp_id}"),
            PermittingRule::Exact,
            None,
        )
    }

    /// Write `content` as the profile's store file with `mode`, creating a 0700 store directory.
    fn seed(state_dir: &Path, content: &str, mode: u32) -> PathBuf {
        let dir = state_dir.join(GRANTED_RULES_DIR);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .unwrap();
        let path = dir.join(format!("{PROFILE}.toml"));
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    const VALID: &str = r#"version = 1
profile = "agent"

[[grant]]
rp_id = "example.com"
action = "authenticate"
kind = "escalation"
granted_at = "2026-11-11T09:30:00Z"
request_id = "esc-1"
origin = "https://example.com"
rule = "exact"
"#;

    fn assert_disabled(state_dir: &Path, needle: &str) {
        let store = open(state_dir);
        let view = store.profile(&profile()).unwrap();
        let reason = view
            .disabled_reason()
            .unwrap_or_else(|| panic!("expected a disabled store, got {view:?}"));
        assert!(
            reason.contains(needle),
            "reason {reason:?} does not mention {needle:?}"
        );
        assert!(!store.is_granted(&profile(), "example.com"));
    }

    #[test]
    fn round_trip_persists_with_owner_only_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = policy();
        let store = open(tmp.path());
        assert_eq!(
            store.profile(&profile()).unwrap().as_ref(),
            &ProfileGrants::Enabled(Vec::new())
        );
        let credential = CredentialRef::with_default_domain(b"cred");
        store
            .add(&policy, &profile(), escalation("Example.COM"), 64)
            .unwrap();
        store
            .add(
                &policy,
                &profile(),
                GrantedRule::new(
                    "example.com",
                    GrantKind::Registration,
                    "esc-2",
                    "https://example.com",
                    PermittingRule::Exact,
                    Some(credential.clone()),
                ),
                64,
            )
            .unwrap();

        let dir = tmp.path().join(GRANTED_RULES_DIR);
        let file = store.path_for(&profile());
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);

        let reopened = open(tmp.path());
        assert_eq!(
            reopened.profile(&profile()).unwrap().as_ref(),
            store.profile(&profile()).unwrap().as_ref()
        );
        assert_eq!(reopened.profile(&profile()).unwrap().rules().len(), 2);
        assert!(reopened.is_granted(&profile(), "example.com"));
        assert!(!reopened.is_granted(&profile(), "other.example"));
        assert_eq!(
            reopened.granted_credential_refs(&profile(), "example.com"),
            vec![credential]
        );
        assert_eq!(
            reopened.grants_digest(&profile()),
            store.grants_digest(&profile())
        );
        let content = fs::read_to_string(&file).unwrap();
        assert!(content.starts_with("version = 1\n"), "{content}");
        assert!(content.contains("[[grant]]"), "{content}");
    }

    #[test]
    fn identical_add_is_not_written_twice() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = policy();
        let store = open(tmp.path());
        let epoch = policy.grant_epoch();
        assert!(matches!(
            store.add(&policy, &profile(), escalation("example.com"), 64),
            Ok(AddOutcome::Added { .. })
        ));
        assert_eq!(
            store.add(&policy, &profile(), escalation("example.com"), 64),
            Ok(AddOutcome::AlreadyGranted)
        );
        assert_eq!(policy.grant_epoch(), epoch + 1);
        assert_eq!(store.profile(&profile()).unwrap().rules().len(), 1);
    }

    #[test]
    fn add_rejects_wildcard_and_invalid_rp_ids_and_the_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = policy();
        let store = open(tmp.path());
        assert!(matches!(
            store.add(&policy, &profile(), escalation("*"), 64),
            Err(GrantStoreError::InvalidRpId(_))
        ));
        assert!(matches!(
            store.add(&policy, &profile(), escalation("https://example.com"), 64),
            Err(GrantStoreError::InvalidRpId(_))
        ));
        store
            .add(&policy, &profile(), escalation("example.com"), 1)
            .unwrap();
        assert_eq!(
            store.add(&policy, &profile(), escalation("other.example"), 1),
            Err(GrantStoreError::CapReached(1))
        );
        let unknown = ProfileId::new("nobody").unwrap();
        assert!(matches!(
            store.add(&policy, &unknown, escalation("example.com"), 64),
            Err(GrantStoreError::UnknownProfile(_))
        ));
    }

    #[test]
    fn leftover_tmp_file_is_ignored_and_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), VALID, 0o600);
        let leftover = tmp.path().join(GRANTED_RULES_DIR).join(".agent.toml.tmp");
        fs::write(&leftover, "garbage from a crash").unwrap();

        let store = open(tmp.path());
        assert!(store.is_granted(&profile(), "example.com"));
        store
            .add(&policy(), &profile(), escalation("other.example"), 64)
            .unwrap();
        assert!(!leftover.exists());
        assert!(open(tmp.path()).is_granted(&profile(), "other.example"));
    }

    #[test]
    fn corrupt_store_disables_grants() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), "this is not = = toml", 0o600);
        assert_disabled(tmp.path(), "does not parse");
    }

    #[test]
    fn unknown_field_disables_grants() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), &format!("{VALID}extra = true\n"), 0o600);
        assert_disabled(tmp.path(), "does not parse");
    }

    #[test]
    fn unknown_version_disables_grants() {
        let tmp = tempfile::tempdir().unwrap();
        seed(
            tmp.path(),
            &VALID.replace("version = 1", "version = 2"),
            0o600,
        );
        assert_disabled(tmp.path(), "unknown version 2");
    }

    #[test]
    fn invalid_rp_id_disables_grants() {
        let tmp = tempfile::tempdir().unwrap();
        seed(
            tmp.path(),
            &VALID.replace("rp_id = \"example.com\"", "rp_id = \"Example.com:443\""),
            0o600,
        );
        assert_disabled(tmp.path(), "rp_id");
    }

    #[test]
    fn wrong_owner_disables_grants() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), VALID, 0o600);
        let other_uid = own_uid().wrapping_add(1);
        let store = GrantedRulesStore::open_with_owner(tmp.path(), [profile()], other_uid);
        let reason = store
            .profile(&profile())
            .unwrap()
            .disabled_reason()
            .unwrap()
            .to_string();
        assert!(reason.contains("owned by uid"), "{reason}");
        assert!(!store.is_granted(&profile(), "example.com"));
    }

    #[test]
    fn group_readable_store_disables_grants() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), VALID, 0o640);
        assert_disabled(tmp.path(), "mode 0640");
    }

    #[test]
    fn store_directory_must_be_owner_only() {
        for mode in [0o755, 0o750, 0o705, 0o770, 0o777, 0o722] {
            let tmp = tempfile::tempdir().unwrap();
            let path = seed(tmp.path(), VALID, 0o600);
            let dir = path.parent().unwrap();
            fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
            assert_disabled(tmp.path(), &format!("mode {mode:04o}"));
            let err = write_atomically(dir, &profile(), b"x", unsafe { libc::geteuid() })
                .expect_err("a group- or world-accessible directory is not written");
            assert!(err.to_string().contains("(0700)"), "{err}");
        }
        let tmp = tempfile::tempdir().unwrap();
        let path = seed(tmp.path(), VALID, 0o600);
        let dir = path.parent().unwrap();
        assert!(
            open_store_dir(dir, false, unsafe { libc::geteuid() })
                .unwrap()
                .is_some()
        );
        assert!(open(tmp.path()).is_granted(&profile(), "example.com"));
    }

    /// Review L4: a store directory that is a symlink is refused, for reads and for writes, and
    /// nothing is written through it.
    #[test]
    fn a_symlinked_store_directory_disables_grants_and_is_never_written_through() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        fs::set_permissions(elsewhere.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // A well-formed store behind the link would otherwise load.
        fs::write(elsewhere.path().join(format!("{PROFILE}.toml")), VALID).unwrap();
        fs::set_permissions(
            elsewhere.path().join(format!("{PROFILE}.toml")),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), tmp.path().join(GRANTED_RULES_DIR)).unwrap();

        assert_disabled(tmp.path(), "symlink");
        let store = open(tmp.path());
        assert!(!store.is_granted(&profile(), "example.com"));

        // Writes refuse as well, and the link target is untouched.
        let err = write_atomically(
            &tmp.path().join(GRANTED_RULES_DIR),
            &profile(),
            b"x",
            own_uid(),
        )
        .expect_err("a symlinked store directory is not written through");
        assert!(err.to_string().contains("symlink"), "{err}");
        let policy = policy();
        assert!(
            store
                .add(&policy, &profile(), escalation("other.example"), 64)
                .is_err()
        );
        let names: Vec<_> = fs::read_dir(elsewhere.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![format!("{PROFILE}.toml")],
            "nothing was created"
        );
        assert_eq!(
            fs::read_to_string(elsewhere.path().join(format!("{PROFILE}.toml"))).unwrap(),
            VALID
        );
    }

    /// Review L4: a symlink planted where the temporary file goes is replaced by the exclusive
    /// create, never followed, and the link's target is left alone.
    #[test]
    fn a_symlink_planted_at_the_temporary_file_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = seed(tmp.path(), VALID, 0o600);
        let dir = path.parent().unwrap().to_path_buf();
        let victim = tmp.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(".agent.toml.tmp")).unwrap();

        let store = open(tmp.path());
        store
            .add(&policy(), &profile(), escalation("other.example"), 64)
            .unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert!(open(tmp.path()).is_granted(&profile(), "other.example"));
        assert!(!dir.join(".agent.toml.tmp").exists());
    }

    /// Review L4: a symlink planted at the store file itself is replaced by the rename (it is not
    /// followed), so the write never lands in the link's target.
    #[test]
    fn a_symlink_planted_at_the_store_file_is_replaced_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(GRANTED_RULES_DIR);
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let victim = tmp.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        let store_file = dir.join(format!("{PROFILE}.toml"));
        std::os::unix::fs::symlink(&victim, &store_file).unwrap();
        // Loading refuses the link.
        assert_disabled(tmp.path(), "symlink");
        // A direct write replaces the link with a regular file and leaves the target alone.
        write_atomically(&dir, &profile(), VALID.as_bytes(), own_uid()).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert!(
            !fs::symlink_metadata(&store_file)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(open(tmp.path()).is_granted(&profile(), "example.com"));
    }

    #[test]
    fn a_store_directory_that_is_a_plain_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(GRANTED_RULES_DIR), "not a directory").unwrap();
        assert_disabled(tmp.path(), "not a directory");
    }

    #[test]
    fn a_missing_store_directory_is_an_empty_store_and_is_created_on_the_first_write() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state").join("agent");
        let store = open(&state);
        assert!(
            store
                .profile(&profile())
                .unwrap()
                .disabled_reason()
                .is_none()
        );
        store
            .add(&policy(), &profile(), escalation("example.com"), 64)
            .unwrap();
        let dir = state.join(GRANTED_RULES_DIR);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o7777, 0o700);
        assert!(open(&state).is_granted(&profile(), "example.com"));
    }

    #[test]
    fn a_symlinked_state_directory_is_the_operators_choice_and_resolves() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-state");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("state-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let store = open(&link);
        store
            .add(&policy(), &profile(), escalation("example.com"), 64)
            .unwrap();
        assert!(real.join(GRANTED_RULES_DIR).join("agent.toml").is_file());
        assert!(open(&link).is_granted(&profile(), "example.com"));
    }

    #[test]
    fn symlinked_store_disables_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let path = seed(tmp.path(), VALID, 0o600);
        let real = tmp.path().join("real.toml");
        fs::rename(&path, &real).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert_disabled(tmp.path(), "symlink");
    }

    #[test]
    fn oversize_store_disables_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let padding = format!("# {}\n", "x".repeat(MAX_STORE_FILE_BYTES as usize));
        seed(tmp.path(), &format!("{VALID}{padding}"), 0o600);
        assert_disabled(tmp.path(), "larger than");
    }

    #[test]
    fn duplicate_entry_disables_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let entry = &VALID[VALID.find("[[grant]]").unwrap()..];
        seed(tmp.path(), &format!("{VALID}\n{entry}"), 0o600);
        assert_disabled(tmp.path(), "duplicate");
    }

    #[test]
    fn disabled_profile_refuses_writes_and_keeps_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = seed(tmp.path(), "garbage", 0o600);
        let policy = policy();
        let store = open(tmp.path());
        let (grant_epoch, revocation_epoch) = (policy.grant_epoch(), policy.revocation_epoch());
        assert!(matches!(
            store.add(&policy, &profile(), escalation("example.com"), 64),
            Err(GrantStoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.revoke(
                &policy,
                &profile(),
                "example.com",
                GrantedAction::Authenticate
            ),
            Err(GrantStoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.clear(&policy, &profile()),
            Err(GrantStoreError::Unavailable(_))
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), "garbage");
        assert_eq!(policy.grant_epoch(), grant_epoch);
        assert_eq!(policy.revocation_epoch(), revocation_epoch);
    }

    fn session(policy: &PolicyRuntime) -> Arc<AgentSession> {
        AgentSession::new(SessionBinding {
            profile_id: profile(),
            principal_digest: [0; 32],
            revocation_epoch: policy.revocation_epoch(),
            ttl: Duration::from_secs(600),
        })
    }

    #[test]
    fn add_bumps_only_the_grant_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = policy();
        let store = open(tmp.path());
        let live = session(&policy);
        let (grant_epoch, revocation_epoch) = (policy.grant_epoch(), policy.revocation_epoch());
        let outcome = store
            .add(&policy, &profile(), escalation("example.com"), 64)
            .unwrap();
        assert_eq!(
            outcome,
            AddOutcome::Added {
                grant_epoch: grant_epoch + 1
            }
        );
        assert_eq!(policy.grant_epoch(), grant_epoch + 1);
        assert_eq!(policy.revocation_epoch(), revocation_epoch);
        assert!(
            live.validity(policy.revocation_epoch(), Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn revoke_and_clear_bump_the_revocation_epoch_and_revoke_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = policy();
        let store = open(tmp.path());
        store
            .add(&policy, &profile(), escalation("example.com"), 64)
            .unwrap();
        store
            .add(&policy, &profile(), escalation("other.example"), 64)
            .unwrap();
        let live = session(&policy);
        let (grant_epoch, revocation_epoch) = (policy.grant_epoch(), policy.revocation_epoch());

        assert_eq!(
            store.revoke(
                &policy,
                &profile(),
                "nope.example",
                GrantedAction::Authenticate
            ),
            Err(GrantStoreError::NotFound)
        );
        assert_eq!(policy.revocation_epoch(), revocation_epoch);

        let outcome = store
            .revoke(
                &policy,
                &profile(),
                "EXAMPLE.com",
                GrantedAction::Authenticate,
            )
            .unwrap();
        assert_eq!(outcome.revoked, 1);
        assert_eq!(outcome.revocation_epoch, revocation_epoch + 1);
        assert_eq!(policy.revocation_epoch(), revocation_epoch + 1);
        assert_eq!(policy.grant_epoch(), grant_epoch);
        assert_eq!(
            live.validity(policy.revocation_epoch(), Instant::now()),
            Err(SessionInvalid::EpochChanged)
        );
        assert!(!store.is_granted(&profile(), "example.com"));
        assert!(!open(tmp.path()).is_granted(&profile(), "example.com"));

        let outcome = store.clear(&policy, &profile()).unwrap();
        assert_eq!(outcome.revoked, 1);
        assert_eq!(policy.revocation_epoch(), revocation_epoch + 2);
        assert!(
            open(tmp.path())
                .profile(&profile())
                .unwrap()
                .rules()
                .is_empty()
        );

        let outcome = store.clear(&policy, &profile()).unwrap();
        assert_eq!(outcome.revoked, 0);
        assert_eq!(policy.revocation_epoch(), revocation_epoch + 2);
    }

    #[test]
    fn revoke_request_removes_only_that_escalations_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = policy();
        let store = open(tmp.path());
        store
            .add(&policy, &profile(), escalation("example.com"), 64)
            .unwrap();
        let mut other = escalation("other.example");
        other.request_id = "esc-2".to_string();
        store.add(&policy, &profile(), other, 64).unwrap();
        let revocation_epoch = policy.revocation_epoch();

        assert_eq!(
            store.revoke_request(&policy, &profile(), "esc-unknown"),
            Err(GrantStoreError::NotFound)
        );
        assert_eq!(policy.revocation_epoch(), revocation_epoch);

        let outcome = store.revoke_request(&policy, &profile(), "esc-1").unwrap();
        assert_eq!(outcome.revoked, 1);
        assert_eq!(policy.revocation_epoch(), revocation_epoch + 1);
        assert!(!store.is_granted(&profile(), "example.com"));
        assert!(store.is_granted(&profile(), "other.example"));
        assert!(!open(tmp.path()).is_granted(&profile(), "example.com"));
    }

    #[test]
    fn preseeded_store_upgrades_request_to_allow_through_resolve() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), VALID, 0o600);
        let store = Arc::new(open(tmp.path()));
        let policy = PolicyRuntime::new(&config(), Arc::new(SystemClock), None)
            .unwrap()
            .with_grant_source(store.clone());

        let granted = policy.resolve(&profile(), &GrantAction::Authenticate, "example.com");
        assert_eq!(granted.configured, RuleAction::Request);
        assert_eq!(granted.action, RuleAction::Allow);
        assert!(granted.granted);

        let other = policy.resolve(&profile(), &GrantAction::Authenticate, "other.example");
        assert_eq!(other.action, RuleAction::Request);
        assert!(!other.granted);

        let register = policy.resolve(&profile(), &GrantAction::Register, "example.com");
        assert_eq!(register.action, RuleAction::Deny);

        // Revoking the grant takes the upgrade away on the next resolution.
        store
            .revoke(
                &policy,
                &profile(),
                "example.com",
                GrantedAction::Authenticate,
            )
            .unwrap();
        let revoked = policy.resolve(&profile(), &GrantAction::Authenticate, "example.com");
        assert_eq!(revoked.action, RuleAction::Request);
    }

    #[test]
    fn disabled_store_without_state_dir_grants_nothing() {
        let store = GrantedRulesStore::disabled([profile()], "no state dir");
        assert_eq!(
            store.profile(&profile()).unwrap().disabled_reason(),
            Some("no state dir")
        );
        assert!(!store.is_granted(&profile(), "example.com"));
        assert!(matches!(
            store.add(&policy(), &profile(), escalation("example.com"), 64),
            Err(GrantStoreError::Unavailable(_))
        ));
    }

    #[test]
    fn a_revoke_or_clear_after_the_token_refuses_the_add_atomically() {
        // Review M-c, M-d: the token captured when the escalation was raised goes stale with a
        // revoke of its RP (also one that found nothing to remove) or a clear of the profile.
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path());
        let policy = policy();
        let token = store.revoke_token(&profile(), "Example.COM").unwrap();
        assert_eq!(
            store.revoke(
                &policy,
                &profile(),
                "example.com",
                GrantedAction::Authenticate
            ),
            Err(GrantStoreError::NotFound)
        );
        assert_eq!(
            store.add_unless_revoked(
                &policy,
                &profile(),
                escalation("example.com"),
                64,
                Some(token)
            ),
            Err(GrantStoreError::Revoked)
        );
        assert!(!store.is_granted(&profile(), "example.com"));

        // Another RP's token is unaffected by that revoke.
        let other = store.revoke_token(&profile(), "other.example").unwrap();
        store
            .add_unless_revoked(
                &policy,
                &profile(),
                escalation("other.example"),
                64,
                Some(other),
            )
            .unwrap();
        assert!(store.is_granted(&profile(), "other.example"));

        // A fresh token works; a clear makes every token of the profile stale.
        let fresh = store.revoke_token(&profile(), "example.com").unwrap();
        let before_clear = store.revoke_token(&profile(), "third.example").unwrap();
        store
            .add_unless_revoked(
                &policy,
                &profile(),
                escalation("example.com"),
                64,
                Some(fresh),
            )
            .unwrap();
        store.clear(&policy, &profile()).unwrap();
        assert_eq!(
            store.add_unless_revoked(
                &policy,
                &profile(),
                escalation("third.example"),
                64,
                Some(before_clear)
            ),
            Err(GrantStoreError::Revoked)
        );
        assert!(store.profile(&profile()).unwrap().rules().is_empty());
    }

    #[test]
    fn rfc3339_formats_utc_seconds() {
        assert_eq!(rfc3339_utc(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_794_389_400)),
            "2026-11-11T09:30:00Z"
        );
        assert_eq!(
            rfc3339_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "2000-02-29T00:00:00Z"
        );
    }
}
