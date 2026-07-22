use passless_core::error::{Error, Result};

use std::path::{Path, PathBuf};

use log::{debug, warn};

/// Find the nearest `.gpg-id` file by walking from `target`'s parent
/// directory up to `store_root`. Returns the path and raw content.
pub fn find_nearest_gpg_id(store_root: &Path, target: &Path) -> Result<(PathBuf, String)> {
    if !target.starts_with(store_root) {
        return Err(Error::Storage(format!(
            "Target path '{}' is not within store root '{}'",
            target.display(),
            store_root.display()
        )));
    }

    let parent = target.parent().ok_or_else(|| {
        Error::Storage(format!(
            "Target path '{}' has no parent directory",
            target.display()
        ))
    })?;

    let start_dir = if parent.exists() {
        parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf())
    } else {
        parent.to_path_buf()
    };

    let root = if store_root.exists() {
        store_root
            .canonicalize()
            .unwrap_or_else(|_| store_root.to_path_buf())
    } else {
        store_root.to_path_buf()
    };

    if !start_dir.starts_with(&root) {
        return Err(Error::Storage(format!(
            "Resolved target path '{}' is not within store root '{}'",
            start_dir.display(),
            root.display()
        )));
    }

    let mut current = start_dir;

    loop {
        let gpg_id_path = current.join(".gpg-id");
        debug!("Looking for .gpg-id at: {:?}", gpg_id_path);

        match std::fs::read_to_string(&gpg_id_path) {
            Ok(content) => {
                debug!("Found .gpg-id at: {:?}", gpg_id_path);
                return Ok((gpg_id_path, content));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::Storage(format!(
                    "Failed to read .gpg-id at {}: {}",
                    gpg_id_path.display(),
                    e
                )));
            }
        }

        if current == root {
            break;
        }

        match current.parent() {
            Some(parent) => {
                current = parent.to_path_buf();
            }
            None => break,
        }
    }

    Err(Error::Storage(format!(
        "No .gpg-id file found in any parent directory of '{}' up to store root '{}'. \
         Make sure the password store is initialized with: pass init <gpg-key-id>",
        target.display(),
        store_root.display()
    )))
}

/// Resolve GPG recipients for a target file using hierarchical .gpg-id lookup.
///
/// Walks from `target`'s parent directory up to `store_root` and uses the
/// nearest `.gpg-id` file found. This enforces pass-compatible recipient
/// resolution semantics: a closer `.gpg-id` (e.g. `fido2/.gpg-id`) overrides
/// the root `.gpg-id`.
pub fn resolve_recipients_for_target(
    store_root: &Path,
    target: &Path,
) -> Result<prs_lib::Recipients> {
    let (gpg_id_path, content) = find_nearest_gpg_id(store_root, target)?;
    parse_gpg_id_content(&content, &gpg_id_path)
}

/// Parse GPG key IDs from .gpg-id file content.
///
/// Security properties:
/// - Strips blank lines, comments (lines starting with `#`) and optional GPG
///   subkey `!` markers.
/// - Rejects short 8-character key IDs (insecure).
/// - Fails when the file contains no usable key IDs.
pub fn parse_gpg_id_content(content: &str, gpg_id_path: &Path) -> Result<prs_lib::Recipients> {
    let mut keys: Vec<prs_lib::Key> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let key_id = trimmed.strip_suffix('!').unwrap_or(trimmed);

        let hex_part = key_id
            .strip_prefix("0x")
            .or_else(|| key_id.strip_prefix("0X"))
            .unwrap_or(key_id);

        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            warn!(
                "Non-hex character in GPG key ID '{}' from {:?}, skipping",
                trimmed, gpg_id_path
            );
            continue;
        }

        if hex_part.len() == 8 {
            return Err(Error::Storage(format!(
                "Short 8-character GPG key ID '{}' rejected from .gpg-id at '{}'. \
                 Use a long key ID (16 hex chars) or full fingerprint (40 hex chars).",
                trimmed,
                gpg_id_path.display()
            )));
        }

        debug!("Found GPG key ID: {}", trimmed);
        keys.push(prs_lib::Key::Gpg(prs_lib::crypto::proto::gpg::Key {
            fingerprint: key_id.to_string(),
            user_ids: vec![],
        }));
    }

    if keys.is_empty() {
        return Err(Error::Storage(format!(
            "No valid GPG key IDs found in .gpg-id file at {:?}",
            gpg_id_path
        )));
    }

    debug!(
        "Loaded {} GPG recipient(s) from {:?}",
        keys.len(),
        gpg_id_path
    );
    Ok(prs_lib::Recipients::from(keys))
}

/// Parse GPG key ID strings from `.gpg-id` file content.
/// Returns the last 16 hex chars (long key ID) for each entry, sorted and
/// deduplicated, for comparison with `gpg --list-packets` output.
pub fn parse_raw_key_ids(content: &str) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let key_id = trimmed.strip_suffix('!').unwrap_or(trimmed);
        let hex_part = key_id
            .strip_prefix("0x")
            .or_else(|| key_id.strip_prefix("0X"))
            .unwrap_or(key_id);
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) || hex_part.len() < 16 {
            continue;
        }
        let long_id = if hex_part.len() > 16 {
            hex_part[hex_part.len() - 16..].to_uppercase()
        } else {
            hex_part.to_uppercase()
        };
        if !ids.contains(&long_id) {
            ids.push(long_id);
        }
    }
    ids.sort();
    ids
}
