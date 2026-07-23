use passless_core::Result;

use crate::storage::tpm::migrate;

pub fn migrate(
    credential_id: Option<String>,
    all: bool,
    dry_run: bool,
    backup_dir: Option<String>,
    path: Option<String>,
    tcti: Option<String>,
) -> Result<()> {
    let report =
        migrate::migrate_credentials(credential_id.clone(), all, dry_run, backup_dir, path, tcti)?;

    if report.migrated.is_empty() && report.skipped.is_empty() && report.failed.is_empty() {
        if credential_id.is_some() {
            println!("No credential found with the specified ID.");
        } else {
            println!("No credentials found to migrate.");
        }
        return Ok(());
    }

    for id in &report.migrated {
        if dry_run {
            println!("WOULD MIGRATE: {} (ES256, software key)", id);
        } else {
            println!("MIGRATED: {}", id);
        }
    }

    for (id, reason) in &report.skipped {
        if reason != "already portable" {
            println!("SKIP: {}: {}", id, reason);
        }
    }

    for (id, reason) in &report.failed {
        println!("FAIL: {}: {}", id, reason);
    }

    println!();
    println!("Migration summary:");
    println!("  Migrated:              {}", report.migrated.len());
    println!(
        "  Skipped (already portable): {}",
        report.already_portable_count()
    );
    println!("  Skipped (non-ES256):   {}", report.non_es256_skip_count());
    println!("  Failed:                {}", report.failed.len());

    let has_details = report.non_es256_skip_count() > 0 || !report.failed.is_empty();
    if has_details {
        println!("  Details:");
        for (id, reason) in report
            .skipped
            .iter()
            .chain(report.failed.iter())
            .filter(|(_, r)| r != "already portable")
        {
            println!("    - {}: {}", id, reason);
        }
    }

    if dry_run {
        println!();
        println!("(dry run — no changes were made)");
    }

    Ok(())
}
