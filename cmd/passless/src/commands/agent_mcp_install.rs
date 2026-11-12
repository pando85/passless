//! `passless agent mcp install`: rewrite the Playwright MCP / chrome-devtools-mcp entries of an
//! MCP client's configuration to run through Passless (see [`crate::agent::mcp_clients`] for what
//! is detected and how the entries are rewritten).
//!
//! The default is a dry run that prints a diff. `--yes` writes the file atomically, after saving a
//! `<file>.passless-backup-<UTC timestamp>` copy with the same permissions.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use passless_core::agent::AgentConfig;
use passless_core::agent::config::CdpExposeMode;
use passless_core::{Error, McpAdapterKind, McpInstallClient, Result};

use crate::agent::mcp_clients::{
    self, Outcome, Plan, Roots, Scope, client_name, config_path, skill_dirs, unified_diff,
    utc_timestamp,
};

/// What `agent mcp install` was asked to do.
pub struct InstallRequest<'a> {
    pub client: McpInstallClient,
    pub project: Option<&'a Path>,
    pub yes: bool,
    pub skill: bool,
    /// `--passless-path`.
    pub passless_path: Option<&'a Path>,
}

/// The `passless` an install writes into the entries, and what to tell the user about it.
#[derive(Debug, PartialEq, Eq)]
pub struct ResolvedPassless {
    pub path: String,
    pub notes: Vec<String>,
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Whether `path` is inside a cargo `target/` directory.
fn in_cargo_target(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "target")
}

/// Which `passless` the entries run: `--passless-path`, else the first `passless` on `PATH`
/// (canonicalized), else this executable. The install may run from a development build while the
/// daemon and the wrapper are the installed package: an entry that points at a `target/` binary
/// would break or drift when that build goes away or changes.
pub fn resolve_passless(
    explicit: Option<&Path>,
    path_var: Option<&std::ffi::OsStr>,
    current_exe: std::io::Result<PathBuf>,
) -> Result<ResolvedPassless> {
    let running = current_exe
        .as_ref()
        .ok()
        .and_then(|exe| fs::canonicalize(exe).ok());
    let (path, source) = if let Some(explicit) = explicit {
        if !explicit.is_absolute() {
            return Err(Error::Other(format!(
                "--passless-path {} must be an absolute path",
                explicit.display()
            )));
        }
        if !is_executable_file(explicit) {
            return Err(Error::Other(format!(
                "--passless-path {} is not an executable file",
                explicit.display()
            )));
        }
        (explicit.to_path_buf(), "--passless-path")
    } else if let Some(found) = path_var
        .into_iter()
        .flat_map(|paths| std::env::split_paths(paths).collect::<Vec<_>>())
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("passless"))
        .find(|candidate| is_executable_file(candidate))
        .and_then(|candidate| fs::canonicalize(candidate).ok())
    {
        (found, "the first `passless` on PATH")
    } else {
        let command = super::agent_browser::mcp_entry_command(current_exe);
        (PathBuf::from(command), "this executable")
    };
    let text = path
        .to_str()
        .filter(|text| !text.contains(['\'', '"']))
        .ok_or_else(|| {
            Error::Other(format!(
                "the passless path {} is not valid UTF-8 or holds a quote",
                path.display()
            ))
        })?
        .to_owned();
    let mut notes = Vec::new();
    let same_as_running = running
        .as_ref()
        .is_some_and(|exe| fs::canonicalize(&path).ok().as_ref() == Some(exe));
    if !same_as_running && source != "this executable" {
        notes.push(format!(
            "note: the entries run {text} ({source}), not this executable{}",
            running
                .as_ref()
                .map(|exe| format!(" {}", exe.display()))
                .unwrap_or_default()
        ));
    }
    if in_cargo_target(&path) {
        notes.push(format!(
            "warning: {text} is inside a cargo target/ directory and can disappear or change with the next build; pass --passless-path <installed passless> to use another"
        ));
    }
    Ok(ResolvedPassless { path: text, notes })
}

/// Refuse a binary that does not have the wrapper: `<passless> agent mcp playwright --help`.
pub fn verify_wrapper(passless: &str) -> Result<()> {
    let output = std::process::Command::new(passless)
        .args(["agent", "mcp", "playwright", "--help"])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Error::Other(format!("cannot run {passless}: {e}")))?;
    let help = String::from_utf8_lossy(&output.stdout);
    if output.status.success() && help.contains("--package") {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "{passless} does not support `agent mcp playwright` (is it older than 0.22.0?): refusing to point the entries at it; pass --passless-path <a newer passless>"
        )))
    }
}

/// The profile an install points the entries at: the requested one, or the only configured
/// profile that exposes a CDP port. The adapters refuse pipe mode, so a profile that is missing
/// or in pipe mode is an error here and not a broken entry later.
pub fn select_profile(
    config: Option<&AgentConfig>,
    requested: Option<&str>,
) -> std::result::Result<String, String> {
    let profiles = config.map(|config| &config.profiles);
    let Some(profiles) = profiles.filter(|profiles| !profiles.is_empty()) else {
        return Err(
            "no agent profile is configured (or the configuration cannot be read: see \
             PASSLESS_CONFIG): define [agents.profiles.<name>] with browser_cdp_expose = \"port\" \
             (docs/agents/quick-start.md) and pass --profile <name>"
                .to_string(),
        );
    };
    let names = || profiles.keys().cloned().collect::<Vec<_>>().join(", ");
    let is_port = |name: &str| {
        profiles
            .get(name)
            .is_some_and(|profile| profile.browser_cdp_expose == Some(CdpExposeMode::Port))
    };
    if let Some(name) = requested {
        if !profiles.contains_key(name) {
            return Err(format!(
                "agent profile '{name}' is not configured (configured: {})",
                names()
            ));
        }
        if !is_port(name) {
            return Err(format!(
                "agent profile '{name}' has browser_cdp_expose = \"pipe\" (the default): the MCP \
                 adapters need a CDP endpoint, which only browser_cdp_expose = \"port\" provides. \
                 Set it in [agents.profiles.{name}] and restart passless, or pick another profile"
            ));
        }
        return Ok(name.to_string());
    }
    let usable: Vec<&String> = profiles.keys().filter(|name| is_port(name)).collect();
    match usable.as_slice() {
        [only] => Ok((*only).clone()),
        [] => Err(format!(
            "no configured agent profile uses browser_cdp_expose = \"port\" (configured: {}): \
             the MCP adapters need it. Set it on one profile and pass --profile <name>",
            names()
        )),
        several => Err(format!(
            "several agent profiles use browser_cdp_expose = \"port\" ({}): pass --profile <name>",
            several
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// `<file>.passless-backup-<UTC timestamp>`, next to the file.
pub fn backup_path(file: &Path, now: SystemTime) -> PathBuf {
    let stamp = utc_timestamp(now.duration_since(UNIX_EPOCH).unwrap_or_default());
    let mut name = file.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".passless-backup-{stamp}"));
    file.with_file_name(name)
}

/// Copy `source` to a new backup file with the same permission bits (a config file can hold
/// secrets: the backup is never more readable than the original). Never overwrites a backup.
pub fn write_backup(source: &Path, now: SystemTime) -> Result<PathBuf> {
    let content = fs::read(source)?;
    let mode = fs::metadata(source)?.permissions().mode() & 0o7777;
    let base = backup_path(source, now);
    for attempt in 0..100 {
        let candidate = if attempt == 0 {
            base.clone()
        } else {
            let mut name = base.file_name().unwrap_or_default().to_os_string();
            name.push(format!("-{attempt}"));
            base.with_file_name(name)
        };
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&candidate)
        {
            Ok(mut file) => {
                file.write_all(&content)?;
                file.sync_all()?;
                // `mode` is subject to the umask: restore the original bits.
                fs::set_permissions(&candidate, fs::Permissions::from_mode(mode))?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(Error::Other(format!(
                    "cannot write the backup {}: {e}",
                    candidate.display()
                )));
            }
        }
    }
    Err(Error::Other(format!(
        "cannot find a free backup name for {}",
        source.display()
    )))
}

/// Replace `path` with `new` atomically: a temporary file in the same directory (same
/// permissions and owner), fsync, rename. A symlink is followed, so the link stays a link. It
/// refuses when the file no longer holds `expected`: the client rewrites some of these files
/// itself, and an edit based on a stale read would drop its changes.
pub fn write_atomic(path: &Path, expected: &[u8], new: &[u8]) -> Result<()> {
    let target = fs::canonicalize(path)?;
    let metadata = fs::metadata(&target)?;
    let dir = target
        .parent()
        .ok_or_else(|| Error::Other(format!("{} has no parent directory", target.display())))?;
    let name = target.file_name().unwrap_or_default().to_string_lossy();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = dir.join(format!(
        ".{name}.passless-tmp-{}-{nonce}",
        std::process::id()
    ));

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(metadata.permissions().mode() & 0o7777)
            .open(&temp)?;
        file.write_all(new)?;
        std::os::unix::fs::fchown(
            &file,
            Some(metadata_uid(&metadata)),
            Some(metadata_gid(&metadata)),
        )
        .ok();
        file.set_permissions(fs::Permissions::from_mode(
            metadata.permissions().mode() & 0o7777,
        ))?;
        file.sync_all()?;
        drop(file);
        if fs::read(&target)? != expected {
            return Err(Error::Other(format!(
                "{} changed while it was being edited (is the client running?): nothing was written, run the command again",
                target.display()
            )));
        }
        fs::rename(&temp, &target)?;
        fs::File::open(dir).and_then(|dir| dir.sync_all())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn metadata_uid(metadata: &fs::Metadata) -> u32 {
    std::os::unix::fs::MetadataExt::uid(metadata)
}

fn metadata_gid(metadata: &fs::Metadata) -> u32 {
    std::os::unix::fs::MetadataExt::gid(metadata)
}

fn scope_label(scope: &Scope) -> String {
    match scope {
        Scope::User => "user".to_owned(),
        Scope::Project(dir) => format!("project {}", dir.display()),
    }
}

fn adapter_label(adapter: McpAdapterKind) -> &'static str {
    match adapter {
        McpAdapterKind::Playwright => "@playwright/mcp",
        McpAdapterKind::ChromeDevtools => "chrome-devtools-mcp",
    }
}

/// The text of the report on one file (without the diff).
pub fn report(file: &Path, client: McpInstallClient, scope: &Scope, plan: &Plan) -> String {
    let mut out = format!(
        "{} ({}, {})\n",
        file.display(),
        client_name(client),
        scope_label(scope)
    );
    if plan.entries.is_empty() {
        out.push_str("  no Playwright MCP or chrome-devtools-mcp entry found\n");
    }
    for entry in &plan.entries {
        let name = &entry.entry.name;
        let location = entry.entry.location();
        match &entry.outcome {
            Outcome::AlreadyWrapped { adapter, profile } => {
                out.push_str(&format!(
                    "  {name} ({location}): already uses Passless ({}{})\n",
                    adapter_label(*adapter),
                    profile
                        .as_deref()
                        .map(|profile| format!(", profile {profile}"))
                        .unwrap_or_default()
                ));
            }
            Outcome::Rewritten {
                runner,
                adapter,
                argv,
                notes,
                ..
            } => {
                out.push_str(&format!(
                    "  {name} ({location}): {} via {runner} -> {}\n",
                    adapter_label(*adapter),
                    argv[1..].join(" ")
                ));
                for note in notes {
                    out.push_str(&format!("      note: {note}\n"));
                }
            }
            Outcome::Unsupported { adapter, why, .. } => {
                out.push_str(&format!(
                    "  {name} ({location}): starts its own {} browser, but {why}; change it by hand (snippet below)\n",
                    adapter_label(*adapter)
                ));
            }
        }
    }
    out
}

fn absolute_dir(dir: &Path) -> Result<PathBuf> {
    let path = fs::canonicalize(dir).map_err(|e| {
        Error::Other(format!(
            "--project {}: no such directory ({e})",
            dir.display()
        ))
    })?;
    if !path.is_dir() {
        return Err(Error::Other(format!(
            "--project {} is not a directory",
            dir.display()
        )));
    }
    Ok(path)
}

/// The daemon configuration file: `PASSLESS_CONFIG`, else `<config dir>/passless/config.toml`
/// (the resolution of `playwright_mcp::load_agent_config`).
pub fn daemon_config_path(
    env: Option<std::ffi::OsString>,
    config_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    env.map(PathBuf::from)
        .or_else(|| config_dir.map(|dir| dir.join("passless/config.toml")))
}

/// The hint printed when the selected profile pins `browser_cdp_port`: a fixed port is not
/// needed (the MCP wrapper and `agent browser --env` find the endpoint themselves) and can
/// collide with another browser. Only a note: it never changes the exit code or the config.
pub fn cdp_port_note(
    config: Option<&AgentConfig>,
    profile: &str,
    config_path: Option<&Path>,
) -> Option<String> {
    let port = config?
        .profiles
        .get(profile)?
        .browser_cdp_port
        .filter(|port| *port > 0)?;
    let location = config_path
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "the passless config".to_owned());
    Some(format!(
        "note: profile '{profile}' pins browser_cdp_port = {port}; the MCP wrapper finds the \
         browser's endpoint itself, so a fixed port is not needed and can collide with other \
         browsers (e.g. a Firefox or Chrome started with --remote-debugging-port). Remove \
         `browser_cdp_port` from [agents.profiles.{profile}] in {location} unless another tool \
         needs that exact port."
    ))
}

/// `passless agent mcp install`.
pub fn run(profile: Option<&str>, request: &InstallRequest) -> Result<()> {
    let roots = Roots::from_process();
    let scope = match request.project {
        Some(dir) => Scope::Project(absolute_dir(dir)?),
        None => Scope::User,
    };
    let config = super::playwright_mcp::load_agent_config();
    let profile = select_profile(config.as_ref(), profile).map_err(Error::Other)?;
    let resolved = resolve_passless(
        request.passless_path,
        std::env::var_os("PATH").as_deref(),
        std::env::current_exe(),
    )?;
    verify_wrapper(&resolved.path)?;
    for note in &resolved.notes {
        eprintln!("{note}");
    }
    let passless = resolved.path;
    let note = cdp_port_note(
        config.as_ref(),
        &profile,
        daemon_config_path(std::env::var_os("PASSLESS_CONFIG"), dirs::config_dir()).as_deref(),
    );
    let mut failure = None;

    let file = config_path(request.client, &scope, &roots).ok_or_else(|| {
        Error::Other("cannot determine the home directory to find the configuration".to_string())
    })?;
    match fs::read(&file) {
        Ok(bytes) => {
            let text = String::from_utf8(bytes)
                .map_err(|_| Error::Other(format!("{} is not valid UTF-8", file.display())))?;
            if let Err(e) = install_file(
                &file,
                &text,
                request,
                &scope,
                &passless,
                &profile,
                note.as_deref(),
            ) {
                failure = Some(e);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("{}: no such file, nothing to rewrite", file.display());
        }
        Err(e) => {
            return Err(Error::Other(format!("cannot read {}: {e}", file.display())));
        }
    }

    if request.skill {
        install_skill(request, &scope, &roots)?;
    }
    failure.map_or(Ok(()), Err)
}

/// Plan (and with `--yes` write) one file, then print `note` after it, in a dry run and with
/// `--yes` alike. The note never changes the result.
fn install_file(
    file: &Path,
    text: &str,
    request: &InstallRequest,
    scope: &Scope,
    passless: &str,
    profile: &str,
    note: Option<&str>,
) -> Result<()> {
    let result = install_plan(file, text, request, scope, passless, profile);
    if let Some(note) = note {
        println!("\n{note}");
    }
    result
}

fn install_plan(
    file: &Path,
    text: &str,
    request: &InstallRequest,
    scope: &Scope,
    passless: &str,
    profile: &str,
) -> Result<()> {
    let plan = mcp_clients::plan(request.client, text, passless, profile)
        .map_err(|e| Error::Other(format!("{}: {e}", file.display())))?;
    print!("{}", report(file, request.client, scope, &plan));

    for entry in &plan.entries {
        if let Outcome::Unsupported { snippet, .. } = &entry.outcome {
            println!("\nSnippet for {}:\n{snippet}", entry.entry.name);
        }
    }
    if plan.jsonc {
        println!(
            "\n{} has comments or trailing commas, which an automatic edit would lose, so it is \
             not rewritten. Replace the entries by hand with:",
            file.display()
        );
        for entry in plan.rewritten() {
            if let Outcome::Rewritten { snippet, .. } = &entry.outcome {
                println!("\n{snippet}");
            }
        }
        if plan.rewritten().next().is_some() && request.yes {
            return Err(Error::Other(format!(
                "refusing to rewrite {} (JSONC): nothing was written",
                file.display()
            )));
        }
        return Ok(());
    }
    let Some(new_text) = &plan.new_text else {
        println!("\nNothing to change.");
        return Ok(());
    };
    let label = file.to_string_lossy();
    println!(
        "\n{}",
        unified_diff(label.trim_start_matches('/'), text, new_text)
    );
    if !request.yes {
        println!(
            "Dry run: nothing was changed. Run again with --yes to write the file (a backup is saved first)."
        );
        return Ok(());
    }
    let backup = write_backup(file, SystemTime::now())?;
    write_atomic(file, text.as_bytes(), new_text.as_bytes())?;
    println!("Backup: {}\nWritten: {}", backup.display(), file.display());
    println!("Restart the client to load the new MCP command.");
    Ok(())
}

fn install_skill(request: &InstallRequest, scope: &Scope, roots: &Roots) -> Result<()> {
    use super::agent_admin::{InstallStatus, SKILL_CONTENT, SKILL_NAME};

    let (skills, root) = skill_dirs(request.client, scope, roots)
        .ok_or_else(|| Error::Other("cannot determine where the client keeps skills".into()))?;
    let path = skills.join(SKILL_NAME).join("SKILL.md");
    let existing = match fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(Error::Other(format!("cannot read {}: {e}", path.display()))),
    };
    let differs = existing
        .as_deref()
        .is_some_and(|bytes| bytes != SKILL_CONTENT.as_bytes());
    if !request.yes {
        let what = match (&existing, differs) {
            (None, _) => "would be installed",
            (Some(_), true) => "differs and would be replaced (a backup is saved first)",
            (Some(_), false) => "is already current",
        };
        println!("\nSkill {SKILL_NAME}: {} {what}", path.display());
        return Ok(());
    }
    if differs {
        let backup = write_backup(&path, SystemTime::now())?;
        println!("\nSkill backup: {}", backup.display());
    }
    match super::agent_admin::install_skill(&path, &root, differs)? {
        InstallStatus::Installed => println!("Skill {SKILL_NAME}: installed at {}", path.display()),
        InstallStatus::Current => {
            println!("Skill {SKILL_NAME}: already current at {}", path.display())
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
