use passless_core::error::{Error, Result};

use std::path::{Path, PathBuf};

use log::debug;

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

    find_nearest_gpg_id_for_dir(store_root, parent)?.ok_or_else(|| {
        Error::Storage(format!(
            "No .gpg-id file found in any parent directory of '{}' up to store root '{}'. \
             Make sure the password store is initialized with: pass init <gpg-key-id>",
            target.display(),
            store_root.display()
        ))
    })
}

/// Find the effective `.gpg-id` for a directory.
///
/// The lookup starts at `start_dir` itself and walks towards `store_root`,
/// matching `pass`'s closest-policy-wins semantics. `Ok(None)` means that no
/// recipient policy applies to the directory; I/O and containment failures are
/// returned as errors.
pub fn find_nearest_gpg_id_for_dir(
    store_root: &Path,
    start_dir: &Path,
) -> Result<Option<(PathBuf, String)>> {
    if !start_dir.starts_with(store_root) {
        return Err(Error::Storage(format!(
            "Directory '{}' is not within store root '{}'",
            start_dir.display(),
            store_root.display()
        )));
    }

    let start_dir = if start_dir.exists() {
        start_dir
            .canonicalize()
            .unwrap_or_else(|_| start_dir.to_path_buf())
    } else {
        start_dir.to_path_buf()
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
            "Resolved directory '{}' is not within store root '{}'",
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
                return Ok(Some((gpg_id_path, content)));
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

    Ok(None)
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

/// Parse GPG recipient selectors from .gpg-id file content.
///
/// This intentionally matches pass's `set_gpg_recipients` semantics: text after
/// `#` is a comment, empty entries are ignored, and every remaining value is
/// handed to GnuPG as a recipient selector. Do not validate or canonicalize
/// selectors here: GnuPG accepts user IDs, email addresses, key IDs,
/// fingerprints, groups, and its other recipient forms.
///
/// Backslash line continuations are supported: a line ending with `\` is joined
/// with the next line (the `\` and newline are removed).
pub fn parse_gpg_id_selectors(content: &str, gpg_id_path: &Path) -> Result<Vec<String>> {
    // First, handle line continuations: join lines ending with '\'
    let mut joined_lines = Vec::new();
    let mut current_line = String::new();

    for line in content.lines() {
        if let Some(stripped) = line.strip_suffix('\\') {
            // Line continues: strip the backslash and accumulate
            current_line.push_str(stripped);
        } else {
            // Line is complete
            current_line.push_str(line);
            joined_lines.push(current_line);
            current_line = String::new();
        }
    }
    // If there's a remaining line (ended with backslash but no following line)
    if !current_line.is_empty() {
        joined_lines.push(current_line);
    }

    let recipients: Vec<String> = joined_lines
        .iter()
        .filter_map(|line| {
            let recipient = line.split('#').next().unwrap_or("");
            (!recipient.is_empty()).then(|| recipient.to_string())
        })
        .collect();

    if recipients.is_empty() {
        return Err(Error::Storage(format!(
            "No GPG recipients found in .gpg-id file at {:?}",
            gpg_id_path
        )));
    }

    debug!(
        "Loaded {} GPG recipient selector(s) from {:?}",
        recipients.len(),
        gpg_id_path
    );
    Ok(recipients)
}

/// Resolve GPG recipients for prs-lib.
///
/// prs-lib models GPG keys using a field named `fingerprint`, but its GnuPG
/// backend ultimately forwards that value to `gpg --recipient`. Preserve the
/// selector verbatim so GnuPG, rather than Passless, applies recipient matching
/// semantics just like pass does.
pub fn parse_gpg_id_content(content: &str, gpg_id_path: &Path) -> Result<prs_lib::Recipients> {
    let keys = parse_gpg_id_selectors(content, gpg_id_path)?
        .into_iter()
        .map(|selector| {
            prs_lib::Key::Gpg(prs_lib::crypto::proto::gpg::Key {
                fingerprint: selector,
                user_ids: vec![],
            })
        })
        .collect::<Vec<_>>();

    Ok(prs_lib::Recipients::from(keys))
}

/// Parse GPG key ID strings from `.gpg-id` file content.
/// Returns the last 16 hex chars (long key ID) for each entry, sorted and
/// deduplicated, for comparison with `gpg --list-packets` output.
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn directory_lookup_prefers_scope_policy() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let scope = root.join("fido2");
        fs::create_dir_all(&scope).unwrap();
        fs::write(root.join(".gpg-id"), "ROOT\n").unwrap();
        fs::write(scope.join(".gpg-id"), "SCOPE\n").unwrap();

        let (path, content) = find_nearest_gpg_id_for_dir(root, &scope)
            .unwrap()
            .expect("scope should have an effective policy");

        assert_eq!(path, scope.join(".gpg-id"));
        assert_eq!(content, "SCOPE\n");
    }

    #[test]
    fn directory_lookup_inherits_root_policy() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let scope = root.join("fido2");
        fs::create_dir_all(&scope).unwrap();
        fs::write(root.join(".gpg-id"), "ROOT\n").unwrap();

        let (path, content) = find_nearest_gpg_id_for_dir(root, &scope)
            .unwrap()
            .expect("root policy should apply to scope");

        assert_eq!(path, root.join(".gpg-id"));
        assert_eq!(content, "ROOT\n");
    }

    #[test]
    fn pass_compatible_recipient_selectors_are_preserved() {
        let path = Path::new(".gpg-id");
        let selectors = parse_gpg_id_selectors(
            "Jason@zx2c4.com# primary\nDEADBEEF\n0x1234567890ABCDEF!\n# comment\n\n",
            path,
        )
        .unwrap();

        assert_eq!(
            selectors,
            vec!["Jason@zx2c4.com", "DEADBEEF", "0x1234567890ABCDEF!",]
        );
    }

    #[test]
    fn pass_recipient_parsing_matches_password_store_boundary() {
        let path = Path::new(".gpg-id");
        let selectors = parse_gpg_id_selectors(
            "0123456789ABCDEF0123456789ABCDEF01234567\n\\
0123456789ABCDEF\n\\
DEADBEEF\n\\
user@example.com\n\\
0x1234567890ABCDEF\n\\
1234567890ABCDEF!\n\\
group-name\n",
            path,
        )
        .unwrap();

        assert_eq!(
            selectors,
            vec![
                "0123456789ABCDEF0123456789ABCDEF01234567",
                "0123456789ABCDEF",
                "DEADBEEF",
                "user@example.com",
                "0x1234567890ABCDEF",
                "1234567890ABCDEF!",
                "group-name",
            ]
        );
    }

    #[test]
    fn pass_comment_semantics_preserve_pre_comment_whitespace() {
        let path = Path::new(".gpg-id");
        let selectors =
            parse_gpg_id_selectors("alice@example.com # primary\n# comment\n\n", path).unwrap();

        // password-store's sed expression removes the comment, not whitespace
        // preceding '#'. GnuPG, not Passless, decides whether the selector works.
        assert_eq!(selectors, vec!["alice@example.com "]);
    }

    #[test]
    fn whitespace_only_recipient_is_forwarded_like_pass() {
        let path = Path::new(".gpg-id");
        let selectors = parse_gpg_id_selectors("   \n", path).unwrap();
        assert_eq!(selectors, vec!["   "]);
    }

    #[test]
    fn comments_and_empty_lines_without_recipients_fail() {
        let path = Path::new(".gpg-id");
        let error = parse_gpg_id_selectors("# comment\n\n# another\n", path).unwrap_err();
        assert!(error.to_string().contains("No GPG recipients"));
    }

    #[test]
    fn invalid_selector_is_not_rejected_by_parser() {
        let path = Path::new(".gpg-id");
        let selectors = parse_gpg_id_selectors("definitely-not-a-real-recipient\n", path).unwrap();
        assert_eq!(selectors, vec!["definitely-not-a-real-recipient"]);
    }

    #[test]
    fn recipient_order_and_duplicates_are_preserved() {
        let path = Path::new(".gpg-id");
        let selectors = parse_gpg_id_selectors(
            "alice@example.com\nbob@example.com\nalice@example.com\n",
            path,
        )
        .unwrap();
        assert_eq!(
            selectors,
            vec!["alice@example.com", "bob@example.com", "alice@example.com"]
        );
    }

    #[test]
    fn unrelated_subtree_policy_does_not_initialize_scope() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let scope = root.join("fido2");
        let other = root.join("personal");
        fs::create_dir_all(&scope).unwrap();
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join(".gpg-id"), "OTHER\n").unwrap();

        assert!(find_nearest_gpg_id_for_dir(root, &scope).unwrap().is_none());
    }
}
