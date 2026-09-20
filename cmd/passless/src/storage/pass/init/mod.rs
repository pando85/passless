//! Password-store initialization using pure type-state pattern
//!
//! Each state is a separate type, enforcing correct initialization order at compile time.

mod complete;
mod directory_created;
mod gpg_key_selected;
mod store_initialized;
mod uninitialized;

pub use uninitialized::Uninitialized;

use crate::storage::pass::GpgBackend;

use passless_core::error::Result;

use std::path::Path;

/// Initialize password store, prompting user via desktop notifications if needed.
///
/// `store_path` is the password-store / Git repository root. `path` is the
/// Passless-owned relative scope inside that store. Existing recipient policy
/// may be inherited from any `.gpg-id` between that scope and `store_path`.
pub fn ensure_initialized(
    store_path: &Path,
    path: &Path,
    gpg_backend: GpgBackend,
    allow_create_without_prompt: bool,
) -> Result<()> {
    let scope_path = store_path.join(path);
    let init = Uninitialized::new(store_path.to_path_buf(), scope_path, gpg_backend);

    match init.check_if_initialized() {
        Ok(init) => init
            .prompt_user(allow_create_without_prompt)?
            .select_gpg_key()?
            .write_gpg_id()?
            .setup_git()?
            .finish(),
        Err(e) if e.to_string().contains("ALREADY_INITIALIZED") => Ok(()),
        Err(e) => Err(e),
    }
}
