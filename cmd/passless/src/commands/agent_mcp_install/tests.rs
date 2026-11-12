use super::*;

use std::time::Duration;

use tempfile::TempDir;

const PASSLESS: &str = "/usr/bin/passless";

const CALYPSO: &str = r#"{
  "mcpServers": {
    "playwright": {
      "command": "pnpm",
      "args": [
        "dlx",
        "@playwright/mcp@0.0.83",
        "--browser",
        "chromium",
        "--headless",
        "--isolated",
        "--viewport-size",
        "1440,900"
      ]
    }
  }
}
"#;

fn config(profiles: &str) -> AgentConfig {
    toml::from_str(&format!("enabled = true\n{profiles}")).unwrap()
}

fn profile(name: &str, expose: Option<&str>) -> String {
    let expose = expose
        .map(|mode| format!("browser_cdp_expose = \"{mode}\"\n"))
        .unwrap_or_default();
    format!("[profiles.{name}]\nmode = \"same-user\"\nprincipal_user = \"agent\"\n{expose}\n")
}

fn request(client: McpInstallClient, yes: bool) -> InstallRequest<'static> {
    InstallRequest {
        client,
        project: None,
        yes,
        skill: false,
        passless_path: None,
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn project_with(content: &str, mode: u32) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(".mcp.json");
    fs::write(&file, content).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
    (dir, file)
}

// ---- profile selection ------------------------------------------------------------------------

#[test]
fn a_requested_profile_must_exist_and_expose_a_port() {
    let cfg = config(&format!(
        "{}{}",
        profile("agent", Some("port")),
        profile("hardened", None)
    ));
    assert_eq!(select_profile(Some(&cfg), Some("agent")).unwrap(), "agent");

    let missing = select_profile(Some(&cfg), Some("nope")).unwrap_err();
    assert!(
        missing.contains("'nope' is not configured") && missing.contains("agent, hardened"),
        "{missing}"
    );

    // The default is pipe mode: the adapters refuse it, so the installer does too.
    let pipe = select_profile(Some(&cfg), Some("hardened")).unwrap_err();
    assert!(
        pipe.contains("browser_cdp_expose = \"pipe\"") && pipe.contains("\"port\""),
        "{pipe}"
    );

    let explicit_pipe = config(&profile("p", Some("pipe")));
    assert!(select_profile(Some(&explicit_pipe), Some("p")).is_err());
}

#[test]
fn without_a_profile_the_only_usable_one_is_chosen() {
    let one = config(&format!(
        "{}{}",
        profile("agent", Some("port")),
        profile("hardened", None)
    ));
    assert_eq!(select_profile(Some(&one), None).unwrap(), "agent");
    assert_eq!(
        select_profile(Some(&config(&profile("solo", Some("port")))), None).unwrap(),
        "solo"
    );

    let many = config(&format!(
        "{}{}",
        profile("a", Some("port")),
        profile("b", Some("port"))
    ));
    let err = select_profile(Some(&many), None).unwrap_err();
    assert!(err.contains("a, b") && err.contains("--profile"), "{err}");

    let none_usable = config(&profile("hardened", None));
    let err = select_profile(Some(&none_usable), None).unwrap_err();
    assert!(
        err.contains("no configured agent profile uses") && err.contains("hardened"),
        "{err}"
    );
}

#[test]
fn no_configuration_at_all_is_a_clear_error() {
    for cfg in [None, Some(config(""))] {
        let err = select_profile(cfg.as_ref(), Some("agent")).unwrap_err();
        assert!(err.contains("no agent profile is configured"), "{err}");
        assert!(select_profile(cfg.as_ref(), None).is_err());
    }
}

// ---- backup and atomic write ------------------------------------------------------------------

#[test]
fn the_backup_is_named_with_a_utc_timestamp_and_keeps_the_permissions() {
    let (dir, file) = project_with("{\"a\": 1}\n", 0o600);
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    assert_eq!(
        backup_path(&file, now),
        dir.path()
            .join(".mcp.json.passless-backup-20231114T221320Z")
    );
    let backup = write_backup(&file, now).unwrap();
    assert_eq!(fs::read(&backup).unwrap(), b"{\"a\": 1}\n");
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // A second backup in the same second gets another name instead of overwriting the first.
    fs::write(&file, "changed").unwrap();
    let second = write_backup(&file, now).unwrap();
    assert_ne!(second, backup);
    assert_eq!(fs::read(&backup).unwrap(), b"{\"a\": 1}\n");
    assert_eq!(fs::read(&second).unwrap(), b"changed");
}

#[test]
fn the_write_is_atomic_and_keeps_mode_and_symlinks() {
    let (dir, file) = project_with("old\n", 0o640);
    write_atomic(&file, b"old\n", b"new\n").unwrap();
    assert_eq!(fs::read(&file).unwrap(), b"new\n");
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        entries(dir.path()),
        [".mcp.json"],
        "no temporary file is left behind"
    );

    // Through a symlink (a dotfiles manager): the target changes, the link stays a link.
    let real = dir.path().join("real.json");
    fs::write(&real, "old\n").unwrap();
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    write_atomic(&link, b"old\n", b"new\n").unwrap();
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&real).unwrap(), b"new\n");
}

#[test]
fn a_file_that_changed_since_it_was_read_is_not_overwritten() {
    let (dir, file) = project_with("what we read\n", 0o600);
    fs::write(&file, "what the client wrote meanwhile\n").unwrap();
    let err = write_atomic(&file, b"what we read\n", b"new\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("changed while it was being edited"), "{err}");
    assert_eq!(
        fs::read(&file).unwrap(),
        b"what the client wrote meanwhile\n"
    );
    assert_eq!(
        entries(dir.path()),
        [".mcp.json"],
        "the temporary file is removed again"
    );
}

#[test]
fn a_failed_write_leaves_the_original_untouched() {
    let (dir, file) = project_with("old\n", 0o600);
    // A read-only directory: the temporary file cannot be created.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let writable = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.path().join("probe"))
        .is_ok();
    let result = write_atomic(&file, b"old\n", b"new\n");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    if !writable {
        assert!(result.is_err());
    }
    assert_eq!(fs::read(&file).unwrap(), b"old\n");
    assert!(
        !entries(dir.path())
            .iter()
            .any(|name| name.contains("passless-tmp"))
    );
}

// ---- dry run and --yes ------------------------------------------------------------------------

fn install(file: &Path, text: &str, yes: bool) -> Result<()> {
    install_file(
        file,
        text,
        &request(McpInstallClient::ClaudeCode, yes),
        &Scope::Project(file.parent().unwrap().to_owned()),
        PASSLESS,
        "agent",
        None,
    )
}

#[test]
fn a_dry_run_changes_nothing_and_makes_no_backup() {
    let (dir, file) = project_with(CALYPSO, 0o644);
    install(&file, CALYPSO, false).unwrap();
    assert_eq!(fs::read_to_string(&file).unwrap(), CALYPSO);
    assert_eq!(entries(dir.path()), [".mcp.json"]);
}

#[test]
fn yes_writes_the_file_after_a_backup_and_a_second_run_changes_nothing() {
    let (dir, file) = project_with(CALYPSO, 0o640);
    install(&file, CALYPSO, true).unwrap();

    let written = fs::read_to_string(&file).unwrap();
    assert_ne!(written, CALYPSO);
    assert!(
        written.contains("\"command\": \"/usr/bin/passless\""),
        "{written}"
    );
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o640
    );

    let names = entries(dir.path());
    assert_eq!(names.len(), 2, "{names:?}");
    let backup = dir.path().join(
        names
            .iter()
            .find(|n| n.contains("passless-backup-"))
            .unwrap(),
    );
    assert_eq!(
        fs::read_to_string(&backup).unwrap(),
        CALYPSO,
        "the backup is the original"
    );
    let stamp = backup
        .file_name()
        .unwrap()
        .to_string_lossy()
        .rsplit('-')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(stamp.len(), 16, "{stamp}");
    assert!(stamp.ends_with('Z') && stamp.contains('T'), "{stamp}");

    // Idempotent: the entry already uses Passless, no new backup, no change.
    install(&file, &written, true).unwrap();
    assert_eq!(fs::read_to_string(&file).unwrap(), written);
    assert_eq!(entries(dir.path()).len(), 2);
}

#[test]
fn a_jsonc_file_is_refused_with_yes_and_left_alone() {
    let jsonc = "{\n  // mine\n  \"mcpServers\": {\"p\": {\"command\": \"npx\", \"args\": [\"@playwright/mcp\"]}}\n}\n";
    let (dir, file) = project_with(jsonc, 0o600);
    // A dry run only reports.
    install(&file, jsonc, false).unwrap();
    let err = install(&file, jsonc, true).unwrap_err().to_string();
    assert!(
        err.contains("JSONC") && err.contains("nothing was written"),
        "{err}"
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), jsonc);
    assert_eq!(
        entries(dir.path()),
        [".mcp.json"],
        "no backup for a refused write"
    );
    // Comments in a file without browser entries are not a problem.
    let harmless = "{\n  // other tools\n  \"mcpServers\": {}\n}\n";
    install(&file, harmless, true).unwrap();
}

#[test]
fn the_report_says_what_changes_and_what_is_dropped() {
    let plan = mcp_clients::plan(McpInstallClient::ClaudeCode, CALYPSO, PASSLESS, "agent").unwrap();
    let text = report(
        Path::new("/p/.mcp.json"),
        McpInstallClient::ClaudeCode,
        &Scope::Project("/p".into()),
        &plan,
    );
    assert!(
        text.starts_with("/p/.mcp.json (claude-code, project /p)\n"),
        "{text}"
    );
    assert!(text.contains("playwright (mcpServers.playwright): @playwright/mcp via pnpm dlx -> agent mcp playwright --profile agent --package @playwright/mcp@0.0.83 -- --isolated --viewport-size 1440,900"), "{text}");
    assert!(
        text.contains(
            "note: dropped `--headless`: headed or headless comes from the Passless profile"
        ),
        "{text}"
    );
    assert!(text.contains("note: dropped `--browser`"), "{text}");

    let wrapped = plan.new_text.unwrap();
    let plan =
        mcp_clients::plan(McpInstallClient::ClaudeCode, &wrapped, PASSLESS, "agent").unwrap();
    let text = report(
        Path::new("/p/.mcp.json"),
        McpInstallClient::ClaudeCode,
        &Scope::User,
        &plan,
    );
    assert!(
        text.contains("already uses Passless (@playwright/mcp, profile agent)"),
        "{text}"
    );
}

#[test]
fn the_project_directory_must_exist() {
    assert!(absolute_dir(Path::new("/nonexistent/passless-test")).is_err());
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f");
    fs::write(&file, "").unwrap();
    assert!(
        absolute_dir(&file)
            .unwrap_err()
            .to_string()
            .contains("not a directory")
    );
    assert!(absolute_dir(dir.path()).is_ok());
}

// ---- the bundled skill ------------------------------------------------------------------------

fn skill_roots(home: &Path) -> Roots {
    Roots {
        home: Some(home.to_owned()),
        ..Roots::default()
    }
}

fn skill_request(client: McpInstallClient, yes: bool) -> InstallRequest<'static> {
    InstallRequest {
        skill: true,
        ..request(client, yes)
    }
}

#[test]
fn the_bundled_skill_describes_the_current_release() {
    use super::super::agent_admin::SKILL_CONTENT;
    for needle in [
        "passless agent mcp playwright",
        "`allow`",
        "`request`",
        "`deny`",
        "bring the page to the front",
        "page.bringToFront()",
        "Passkey autofill does not work",
        "passless agent mcp install",
    ] {
        assert!(SKILL_CONTENT.contains(needle), "the skill lacks {needle:?}");
    }
    // Vocabulary and commands of earlier releases.
    for stale in [
        "playwright-mcp --profile",
        "agent playwright-mcp",
        "confirm",
        "9222",
        "conditional mediation",
    ] {
        assert!(
            !SKILL_CONTENT.contains(stale),
            "the skill still says {stale:?}"
        );
    }
}

#[test]
fn a_skill_is_installed_replaced_after_a_backup_and_then_current() {
    use super::super::agent_admin::SKILL_CONTENT;
    let home = tempfile::tempdir().unwrap();
    let roots = skill_roots(home.path());
    let skill = home
        .path()
        .join(".config/opencode/skills/passless-agent/SKILL.md");
    let client = McpInstallClient::Opencode;

    // A dry run installs nothing.
    install_skill(&skill_request(client, false), &Scope::User, &roots).unwrap();
    assert!(!skill.exists());

    install_skill(&skill_request(client, true), &Scope::User, &roots).unwrap();
    assert_eq!(fs::read_to_string(&skill).unwrap(), SKILL_CONTENT);
    assert_eq!(entries(skill.parent().unwrap()), ["SKILL.md"]);

    // Current: nothing to do, no backup.
    install_skill(&skill_request(client, true), &Scope::User, &roots).unwrap();
    assert_eq!(entries(skill.parent().unwrap()), ["SKILL.md"]);

    // A stale copy is backed up, then replaced; a dry run leaves it alone.
    fs::write(&skill, "stale skill\n").unwrap();
    install_skill(&skill_request(client, false), &Scope::User, &roots).unwrap();
    assert_eq!(fs::read_to_string(&skill).unwrap(), "stale skill\n");
    install_skill(&skill_request(client, true), &Scope::User, &roots).unwrap();
    assert_eq!(fs::read_to_string(&skill).unwrap(), SKILL_CONTENT);
    let names = entries(skill.parent().unwrap());
    let backup = names
        .iter()
        .find(|n| n.starts_with("SKILL.md.passless-backup-"))
        .expect("a backup");
    assert_eq!(
        fs::read_to_string(skill.parent().unwrap().join(backup)).unwrap(),
        "stale skill\n"
    );
}

#[test]
fn claude_code_skills_follow_claude_config_dir() {
    use super::super::agent_admin::SKILL_CONTENT;
    let home = tempfile::tempdir().unwrap();
    let personal = tempfile::tempdir().unwrap();
    let roots = Roots {
        claude_config_dir: Some(personal.path().to_owned()),
        ..skill_roots(home.path())
    };
    install_skill(
        &skill_request(McpInstallClient::ClaudeCode, true),
        &Scope::User,
        &roots,
    )
    .unwrap();
    let installed = personal.path().join("skills/passless-agent/SKILL.md");
    assert_eq!(fs::read_to_string(installed).unwrap(), SKILL_CONTENT);
    assert!(
        !home.path().join(".claude").exists(),
        "the default directory is not touched"
    );

    // Without the variable it is ~/.claude/skills.
    install_skill(
        &skill_request(McpInstallClient::ClaudeCode, true),
        &Scope::User,
        &skill_roots(home.path()),
    )
    .unwrap();
    assert!(
        home.path()
            .join(".claude/skills/passless-agent/SKILL.md")
            .is_file()
    );
}

#[test]
fn the_claude_code_user_config_is_found_through_claude_config_dir() {
    // `CLAUDE_CONFIG_DIR=~/.claude-personal`: the user-scope servers are in its `.claude.json`.
    let home = tempfile::tempdir().unwrap();
    let personal = home.path().join(".claude-personal");
    fs::create_dir_all(&personal).unwrap();
    fs::write(home.path().join(".claude.json"), "{\"mcpServers\": {}}").unwrap();
    fs::write(personal.join(".claude.json"), CALYPSO).unwrap();
    let roots = Roots {
        claude_config_dir: Some(personal.clone()),
        ..skill_roots(home.path())
    };
    let file = config_path(McpInstallClient::ClaudeCode, &Scope::User, &roots).unwrap();
    assert_eq!(file, personal.join(".claude.json"));
    install(&file, &fs::read_to_string(&file).unwrap(), true).unwrap();
    assert!(
        fs::read_to_string(&file)
            .unwrap()
            .contains("/usr/bin/passless")
    );
    assert_eq!(
        fs::read_to_string(home.path().join(".claude.json")).unwrap(),
        "{\"mcpServers\": {}}"
    );
}

// ---- which passless the entries run -----------------------------------------------------------

fn fake_passless(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("passless");
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn exe_in(dir: &Path) -> std::io::Result<PathBuf> {
    let path = dir.join("running-passless");
    fs::write(&path, "").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    Ok(path)
}

#[test]
fn an_explicit_passless_path_wins() {
    let bin = tempfile::tempdir().unwrap();
    let on_path = tempfile::tempdir().unwrap();
    let explicit = fake_passless(bin.path(), "");
    fake_passless(on_path.path(), "");
    let resolved = resolve_passless(
        Some(&explicit),
        Some(on_path.path().as_os_str()),
        exe_in(bin.path()),
    )
    .unwrap();
    assert_eq!(resolved.path, explicit.to_str().unwrap());
    assert!(
        resolved
            .notes
            .iter()
            .any(|n| n.starts_with("note:") && n.contains("--passless-path")),
        "{resolved:?}"
    );

    // Relative, missing and non-executable paths are errors.
    assert!(resolve_passless(Some(Path::new("passless")), None, exe_in(bin.path())).is_err());
    assert!(resolve_passless(Some(&bin.path().join("nope")), None, exe_in(bin.path())).is_err());
    fs::set_permissions(&explicit, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(resolve_passless(Some(&explicit), None, exe_in(bin.path())).is_err());
}

#[test]
fn without_an_option_the_first_passless_on_path_is_used_canonicalized() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let running = tempfile::tempdir().unwrap();
    let real = fake_passless(second.path(), "");
    // The first PATH entry has a symlink: the canonical target is written.
    let link_dir = first.path().join("bin");
    fs::create_dir(&link_dir).unwrap();
    std::os::unix::fs::symlink(&real, link_dir.join("passless")).unwrap();
    let path = std::env::join_paths([
        Path::new("relative/bin"),
        Path::new("/nonexistent/bin"),
        link_dir.as_path(),
        second.path(),
    ])
    .unwrap();
    let resolved = resolve_passless(None, Some(&path), exe_in(running.path())).unwrap();
    assert_eq!(
        resolved.path,
        fs::canonicalize(&real).unwrap().to_str().unwrap()
    );
    assert!(
        resolved
            .notes
            .iter()
            .any(|n| n.starts_with("note:") && n.contains("PATH")),
        "{resolved:?}"
    );
}

#[test]
fn the_running_executable_is_the_last_resort_and_needs_no_note() {
    let running = tempfile::tempdir().unwrap();
    let exe = exe_in(running.path()).unwrap();
    let empty = tempfile::tempdir().unwrap();
    let resolved = resolve_passless(None, Some(empty.path().as_os_str()), Ok(exe.clone())).unwrap();
    assert_eq!(
        resolved.path,
        fs::canonicalize(&exe).unwrap().to_str().unwrap()
    );
    assert!(resolved.notes.is_empty(), "{resolved:?}");
    // No PATH at all behaves the same; and a PATH hit that is the running binary needs no note either.
    assert_eq!(
        resolve_passless(None, None, Ok(exe.clone())).unwrap(),
        resolved
    );
    let fake = fake_passless(running.path(), "");
    let same = resolve_passless(None, Some(running.path().as_os_str()), Ok(fake.clone())).unwrap();
    assert!(same.notes.is_empty(), "{same:?}");
}

#[test]
fn a_binary_inside_a_cargo_target_directory_is_a_warning() {
    let root = tempfile::tempdir().unwrap();
    let debug = root.path().join("target/debug");
    fs::create_dir_all(&debug).unwrap();
    let dev = fake_passless(&debug, "");
    let resolved = resolve_passless(Some(&dev), None, exe_in(root.path())).unwrap();
    assert!(
        resolved
            .notes
            .iter()
            .any(|n| n.starts_with("warning:") && n.contains("target/")),
        "{resolved:?}"
    );
    // The running dev build is warned about too, when nothing better is on PATH.
    let from_target = resolve_passless(None, None, Ok(dev.clone())).unwrap();
    assert!(
        from_target.notes.iter().any(|n| n.starts_with("warning:")),
        "{from_target:?}"
    );
    // An installed one is not.
    let bin = tempfile::tempdir().unwrap();
    let installed = fake_passless(bin.path(), "");
    let ok = resolve_passless(Some(&installed), None, exe_in(root.path())).unwrap();
    assert!(
        !ok.notes.iter().any(|n| n.starts_with("warning:")),
        "{ok:?}"
    );
}

#[test]
fn a_passless_without_the_wrapper_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let new = fake_passless(dir.path(), "echo '--package <SPEC>'");
    verify_wrapper(new.to_str().unwrap()).unwrap();
    let old = fake_passless(
        dir.path(),
        "echo \"error: unrecognized subcommand 'mcp'\" >&2; exit 2",
    );
    let err = verify_wrapper(old.to_str().unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("does not support `agent mcp playwright`") && err.contains("--passless-path"),
        "{err}"
    );
    assert!(verify_wrapper("/nonexistent/passless").is_err());
}

// ---- the browser_cdp_port hint ----------------------------------------------------------------

fn pinned(port: Option<u16>) -> AgentConfig {
    let port = port
        .map(|port| format!("browser_cdp_port = {port}\n"))
        .unwrap_or_default();
    config(&format!(
        "[profiles.coding]\nmode = \"same-user\"\nprincipal_user = \"agent\"\nbrowser_cdp_expose = \"port\"\n{port}"
    ))
}

#[test]
fn a_pinned_browser_cdp_port_gets_a_note_naming_the_profile_and_config() {
    let path = Path::new("/home/alice/.config/passless/config.toml");
    let note = cdp_port_note(Some(&pinned(Some(9222))), "coding", Some(path)).unwrap();
    assert_eq!(
        note,
        "note: profile 'coding' pins browser_cdp_port = 9222; the MCP wrapper finds the \
         browser's endpoint itself, so a fixed port is not needed and can collide with other \
         browsers (e.g. a Firefox or Chrome started with --remote-debugging-port). Remove \
         `browser_cdp_port` from [agents.profiles.coding] in \
         /home/alice/.config/passless/config.toml unless another tool needs that exact port."
    );
}

#[test]
fn no_note_without_a_pinned_port() {
    let path = Path::new("/c.toml");
    assert_eq!(
        cdp_port_note(Some(&pinned(None)), "coding", Some(path)),
        None
    );
    assert_eq!(
        cdp_port_note(Some(&pinned(Some(0))), "coding", Some(path)),
        None
    );
    assert_eq!(
        cdp_port_note(Some(&pinned(Some(9222))), "other", Some(path)),
        None
    );
    assert_eq!(cdp_port_note(None, "coding", Some(path)), None);
}

#[test]
fn the_note_follows_passless_config_then_the_default() {
    assert_eq!(
        daemon_config_path(Some("/etc/p.toml".into()), Some("/home/a/.config".into())),
        Some(PathBuf::from("/etc/p.toml"))
    );
    assert_eq!(
        daemon_config_path(None, Some("/home/a/.config".into())),
        Some(PathBuf::from("/home/a/.config/passless/config.toml"))
    );
    assert_eq!(daemon_config_path(None, None), None);
    let note = cdp_port_note(Some(&pinned(Some(9222))), "coding", None).unwrap();
    assert!(note.contains("in the passless config unless"), "{note}");
}

#[test]
fn the_note_changes_neither_the_result_nor_any_file() {
    let note = cdp_port_note(
        Some(&pinned(Some(9222))),
        "coding",
        Some(Path::new("/c.toml")),
    );
    assert!(note.is_some());
    let with_note = |file: &Path, text: &str, yes: bool, note: Option<&str>| {
        install_file(
            file,
            text,
            &request(McpInstallClient::ClaudeCode, yes),
            &Scope::Project(file.parent().unwrap().to_owned()),
            PASSLESS,
            "agent",
            note,
        )
    };

    // A dry run: Ok with and without the note, nothing written.
    let (dir, file) = project_with(CALYPSO, 0o644);
    with_note(&file, CALYPSO, false, note.as_deref()).unwrap();
    with_note(&file, CALYPSO, false, None).unwrap();
    assert_eq!(fs::read_to_string(&file).unwrap(), CALYPSO);
    assert_eq!(entries(dir.path()), [".mcp.json"]);

    // --yes: the same rewrite with the note as without.
    let (_plain_dir, plain) = project_with(CALYPSO, 0o644);
    with_note(&plain, CALYPSO, true, None).unwrap();
    with_note(&file, CALYPSO, true, note.as_deref()).unwrap();
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        fs::read_to_string(&plain).unwrap()
    );

    // A failure stays a failure: JSONC with --yes is refused with the note too.
    let jsonc = "{\n  // mine\n  \"mcpServers\": {\"p\": {\"command\": \"npx\", \"args\": [\"@playwright/mcp\"]}}\n}\n";
    let (_dir, file) = project_with(jsonc, 0o600);
    assert!(with_note(&file, jsonc, true, note.as_deref()).is_err());
    assert!(with_note(&file, jsonc, true, None).is_err());
}
