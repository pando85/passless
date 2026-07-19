#[cfg(feature = "agent")]
mod agent_admin_cli {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use tempfile::tempdir;

    fn passless_bin() -> PathBuf {
        let mut path = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        path.push("passless");
        path
    }

    fn run_install(home: &Path, project: &Path, args: &[&str]) -> (String, String, i32) {
        let bin = passless_bin();
        let mut cmd = Command::new(bin);
        cmd.arg("agent-admin")
            .args(args)
            .env("HOME", home)
            .current_dir(project);
        let output = cmd.output().expect("failed to run passless binary");
        let code = output.status.code().unwrap_or(-1);
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
            code,
        )
    }

    #[test]
    fn install_creates_skill_for_explicit_opencode_user_scope() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();

        let (stdout, _stderr, code) =
            run_install(home.path(), project.path(), &["install", "opencode"]);

        assert_eq!(code, 0, "install failed: {}", _stderr);
        assert!(stdout.contains("Installed"));

        let expected = home
            .path()
            .join(".config/opencode/skills/passless-agent/SKILL.md");
        assert!(
            expected.exists(),
            "skill not created at {}",
            expected.display()
        );

        let content = fs::read(&expected).unwrap();
        assert!(!content.is_empty());
        assert!(content.starts_with(b"---"));
    }

    #[test]
    fn install_creates_skill_for_explicit_claude_project_scope() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();

        let (stdout, _stderr, code) = run_install(
            home.path(),
            project.path(),
            &["install", "claude", "--scope", "project"],
        );

        assert_eq!(code, 0, "install failed: {}", _stderr);
        assert!(stdout.contains("Installed"));

        let expected = project
            .path()
            .join(".claude/skills/passless-agent/SKILL.md");
        assert!(expected.exists());
    }

    #[test]
    fn install_creates_skill_for_explicit_pi_user_scope() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();

        let (stdout, _stderr, code) = run_install(home.path(), project.path(), &["install", "pi"]);

        assert_eq!(code, 0, "install failed: {}", _stderr);
        assert!(stdout.contains("Installed"));

        let expected = home.path().join(".pi/agent/skills/passless-agent/SKILL.md");
        assert!(
            expected.exists(),
            "skill not created at {}",
            expected.display()
        );

        let content = fs::read(&expected).unwrap();
        assert!(!content.is_empty());
        assert!(content.starts_with(b"---"));
    }

    #[test]
    fn install_creates_skill_for_explicit_pi_project_scope() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();

        let (stdout, _stderr, code) = run_install(
            home.path(),
            project.path(),
            &["install", "pi", "--scope", "project"],
        );

        assert_eq!(code, 0, "install failed: {}", _stderr);
        assert!(stdout.contains("Installed"));

        let expected = project.path().join(".pi/skills/passless-agent/SKILL.md");
        assert!(
            expected.exists(),
            "skill not created at {}",
            expected.display()
        );
    }

    #[test]
    fn install_second_run_is_idempotent() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();

        let (stdout1, _, code1) =
            run_install(home.path(), project.path(), &["install", "opencode"]);
        assert_eq!(code1, 0);
        assert!(stdout1.contains("Installed"));

        let (stdout2, _, code2) =
            run_install(home.path(), project.path(), &["install", "opencode"]);
        assert_eq!(code2, 0);
        assert!(stdout2.contains("already current"));
    }

    #[test]
    fn install_force_replaces_different_content() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();

        let (_, _, code1) = run_install(home.path(), project.path(), &["install", "opencode"]);
        assert_eq!(code1, 0);

        let skill_path = home
            .path()
            .join(".config/opencode/skills/passless-agent/SKILL.md");
        fs::write(&skill_path, "custom content").unwrap();

        let (stdout, _, code2) = run_install(
            home.path(),
            project.path(),
            &["install", "opencode", "--force"],
        );
        assert_eq!(code2, 0);
        assert!(stdout.contains("Installed"));

        let content = fs::read_to_string(&skill_path).unwrap();
        assert_ne!(content, "custom content");
        assert!(content.starts_with("---"));
    }

    #[test]
    fn install_without_force_fails_on_different_content() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();

        let (_, _, code1) = run_install(home.path(), project.path(), &["install", "opencode"]);
        assert_eq!(code1, 0);

        let skill_path = home
            .path()
            .join(".config/opencode/skills/passless-agent/SKILL.md");
        fs::write(&skill_path, "custom content").unwrap();

        let (_, stderr, code2) = run_install(home.path(), project.path(), &["install", "opencode"]);
        assert_ne!(code2, 0);
        assert!(stderr.contains("different skill") || stderr.contains("force"));
    }

    #[test]
    fn install_auto_detects_no_agent_fails() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();
        let empty_bin = tempdir().unwrap();

        let bin = passless_bin();
        let mut cmd = Command::new(bin);
        let output = cmd
            .arg("agent-admin")
            .arg("install")
            .env("HOME", home.path())
            .env("PATH", empty_bin.path())
            .current_dir(project.path())
            .output()
            .expect("failed to run passless binary");

        assert_ne!(output.status.code().unwrap_or(-1), 0);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("No supported coding agent"));
    }

    #[test]
    fn install_creates_directory_with_correct_permissions() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();

        let (_, _, code) = run_install(home.path(), project.path(), &["install", "opencode"]);
        assert_eq!(code, 0);

        let skill_dir = home.path().join(".config/opencode/skills/passless-agent");
        assert!(skill_dir.exists());
        let mode = fs::metadata(&skill_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn install_skill_bytes_exactly_match_bundled_asset() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();

        let (_, _, code) = run_install(home.path(), project.path(), &["install", "claude"]);
        assert_eq!(code, 0);

        let skill_path = home.path().join(".claude/skills/passless-agent/SKILL.md");
        let content = fs::read(&skill_path).unwrap();

        let expected = include_str!("../assets/skills/passless-agent/SKILL.md");
        assert_eq!(content, expected.as_bytes());
    }
}
