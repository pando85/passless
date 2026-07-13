use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use passless_core::{AgentSkillScope, AgentSkillTarget, Error, Result};

const SKILL_NAME: &str = "passless-agent";
const SKILL_CONTENT: &str = include_str!("../../assets/skills/passless-agent/SKILL.md");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentKind {
    Opencode,
    Claude,
    Pi,
}

impl AgentKind {
    const ALL: [Self; 3] = [Self::Opencode, Self::Claude, Self::Pi];

    fn name(self) -> &'static str {
        match self {
            Self::Opencode => "OpenCode",
            Self::Claude => "Claude Code",
            Self::Pi => "Pi",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Opencode => "opencode",
            Self::Claude => "claude",
            Self::Pi => "pi",
        }
    }

    fn user_config_path(self, home: &Path) -> PathBuf {
        match self {
            Self::Opencode => home.join(".config/opencode"),
            Self::Claude => home.join(".claude"),
            Self::Pi => home.join(".pi/agent"),
        }
    }

    fn skill_path(self, scope: AgentSkillScope, home: &Path, project: &Path) -> PathBuf {
        let root = match (self, scope) {
            (Self::Opencode, AgentSkillScope::User) => home.join(".config/opencode/skills"),
            (Self::Claude, AgentSkillScope::User) => home.join(".claude/skills"),
            (Self::Pi, AgentSkillScope::User) => home.join(".pi/agent/skills"),
            (Self::Opencode, AgentSkillScope::Project) => project.join(".opencode/skills"),
            (Self::Claude, AgentSkillScope::Project) => project.join(".claude/skills"),
            (Self::Pi, AgentSkillScope::Project) => project.join(".pi/skills"),
        };
        root.join(SKILL_NAME).join("SKILL.md")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallStatus {
    Installed,
    Current,
}

pub fn install(target: AgentSkillTarget, scope: AgentSkillScope, force: bool) -> Result<()> {
    let current_dir = env::current_dir()?;
    let project = project_root(&current_dir);
    let home = dirs::home_dir().ok_or_else(|| {
        Error::Other("Could not determine the home directory for skill installation".to_string())
    })?;
    let agents = selected_agents(target, &home, &project)?;

    for agent in agents {
        let path = agent.skill_path(scope, &home, &project);
        let trusted_root = match scope {
            AgentSkillScope::User => &home,
            AgentSkillScope::Project => &project,
        };
        match install_skill(&path, trusted_root, force)? {
            InstallStatus::Installed => {
                println!(
                    "Installed Passless skill for {} at {}",
                    agent.name(),
                    path.display()
                );
            }
            InstallStatus::Current => {
                println!(
                    "Passless skill for {} is already current at {}",
                    agent.name(),
                    path.display()
                );
            }
        }
    }

    Ok(())
}

fn selected_agents(
    target: AgentSkillTarget,
    home: &Path,
    project: &Path,
) -> Result<Vec<AgentKind>> {
    let explicit = match target {
        AgentSkillTarget::Auto => None,
        AgentSkillTarget::Opencode => Some(AgentKind::Opencode),
        AgentSkillTarget::Claude => Some(AgentKind::Claude),
        AgentSkillTarget::Pi => Some(AgentKind::Pi),
    };
    if let Some(agent) = explicit {
        return Ok(vec![agent]);
    }

    let agents: Vec<_> = AgentKind::ALL
        .into_iter()
        .filter(|agent| agent_is_detected(*agent, home, project))
        .collect();
    if agents.is_empty() {
        return Err(Error::Other(
            "No supported coding agent was detected. Specify one of: opencode, claude, pi"
                .to_string(),
        ));
    }
    Ok(agents)
}

fn agent_is_detected(agent: AgentKind, home: &Path, project: &Path) -> bool {
    agent.user_config_path(home).is_dir()
        || match agent {
            AgentKind::Opencode => project.join(".opencode").is_dir(),
            AgentKind::Claude => project.join(".claude").is_dir(),
            AgentKind::Pi => project.join(".pi").is_dir(),
        }
        || command_exists(agent.command())
}

fn command_exists(command: &str) -> bool {
    env::var_os("PATH").is_some_and(|path| {
        env::split_paths(&path).any(|directory| {
            let candidate = directory.join(command);
            fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
    })
}

fn project_root(current_dir: &Path) -> PathBuf {
    current_dir
        .ancestors()
        .find(|path| path.join(".git").exists())
        .unwrap_or(current_dir)
        .to_path_buf()
}

fn install_skill(path: &Path, trusted_root: &Path, force: bool) -> Result<InstallStatus> {
    let skill_dir = path.parent().ok_or_else(|| {
        Error::Other(format!(
            "Invalid skill installation path: {}",
            path.display()
        ))
    })?;
    reject_symlink_components(trusted_root, skill_dir)?;

    if let Ok(metadata) = fs::symlink_metadata(skill_dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::Other(format!(
                "Refusing to install through non-directory skill path: {}",
                skill_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(skill_dir).map_err(|error| {
            Error::Other(format!(
                "Failed to create skill directory {}: {}",
                skill_dir.display(),
                error
            ))
        })?;
        fs::set_permissions(skill_dir, fs::Permissions::from_mode(0o755))?;
    }
    reject_symlink_components(trusted_root, skill_dir)?;

    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::Other(format!(
                "Refusing to replace non-regular skill file: {}",
                path.display()
            )));
        }
        if fs::read(path)? == SKILL_CONTENT.as_bytes() {
            return Ok(InstallStatus::Current);
        }
        if !force {
            return Err(Error::Other(format!(
                "A different skill already exists at {}. Re-run with --force to replace it",
                path.display()
            )));
        }
    }

    let (temp_path, mut temp) = create_temp_file(skill_dir)?;

    let write_result = (|| -> std::io::Result<()> {
        temp.write_all(SKILL_CONTENT.as_bytes())?;
        temp.sync_all()?;
        drop(temp);

        if force {
            fs::rename(&temp_path, path)?;
        } else {
            fs::hard_link(&temp_path, path)?;
            fs::remove_file(&temp_path)?;
        }
        File::open(skill_dir)?.sync_all()
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp_path);
        if error.kind() == std::io::ErrorKind::AlreadyExists && !force {
            if fs::read(path).is_ok_and(|content| content == SKILL_CONTENT.as_bytes()) {
                return Ok(InstallStatus::Current);
            }
            return Err(Error::Other(format!(
                "A different skill was concurrently installed at {}",
                path.display()
            )));
        }
        return Err(Error::Other(format!(
            "Failed to install skill at {}: {}",
            path.display(),
            error
        )));
    }

    Ok(InstallStatus::Installed)
}

fn reject_symlink_components(trusted_root: &Path, path: &Path) -> Result<()> {
    let relative = path.strip_prefix(trusted_root).map_err(|_| {
        Error::Other(format!(
            "Skill path {} is outside trusted root {}",
            path.display(),
            trusted_root.display()
        ))
    })?;
    let mut current = trusted_root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Other(format!(
                    "Refusing to install through symlinked path component: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn create_temp_file(skill_dir: &Path) -> Result<(PathBuf, File)> {
    for _ in 0..16 {
        let temp_path = skill_dir.join(format!(
            ".SKILL.md.{}.{:016x}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Error::Other(format!(
                    "Failed to create temporary skill file {}: {}",
                    temp_path.display(),
                    error
                )));
            }
        }
    }
    Err(Error::Other(format!(
        "Failed to allocate a temporary skill file in {}",
        skill_dir.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    #[test]
    fn skill_paths_match_agent_conventions() {
        let home = Path::new("/home/test");
        let project = Path::new("/work/project");

        assert_eq!(
            AgentKind::Opencode.skill_path(AgentSkillScope::User, home, project),
            Path::new("/home/test/.config/opencode/skills/passless-agent/SKILL.md")
        );
        assert_eq!(
            AgentKind::Claude.skill_path(AgentSkillScope::Project, home, project),
            Path::new("/work/project/.claude/skills/passless-agent/SKILL.md")
        );
        assert_eq!(
            AgentKind::Pi.skill_path(AgentSkillScope::User, home, project),
            Path::new("/home/test/.pi/agent/skills/passless-agent/SKILL.md")
        );
    }

    #[test]
    fn explicit_selection_does_not_require_detection() {
        let dir = tempdir().unwrap();
        let selected = selected_agents(AgentSkillTarget::Claude, dir.path(), dir.path()).unwrap();
        assert_eq!(selected, vec![AgentKind::Claude]);
    }

    #[test]
    fn auto_selects_configured_agents() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();
        fs::create_dir_all(home.path().join(".config/opencode")).unwrap();
        fs::create_dir_all(home.path().join(".pi/agent")).unwrap();

        let selected =
            selected_agents(AgentSkillTarget::Auto, home.path(), project.path()).unwrap();
        assert!(selected.contains(&AgentKind::Opencode));
        assert!(selected.contains(&AgentKind::Pi));
    }

    #[test]
    fn install_is_idempotent_and_requires_force_for_changes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("skills/passless-agent/SKILL.md");

        assert_eq!(
            install_skill(&path, dir.path(), false).unwrap(),
            InstallStatus::Installed
        );
        assert_eq!(
            install_skill(&path, dir.path(), false).unwrap(),
            InstallStatus::Current
        );

        fs::write(&path, "custom skill").unwrap();
        assert!(install_skill(&path, dir.path(), false).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "custom skill");

        assert_eq!(
            install_skill(&path, dir.path(), true).unwrap(),
            InstallStatus::Installed
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), SKILL_CONTENT);
    }

    #[test]
    fn install_rejects_symlink_target() {
        let dir = tempdir().unwrap();
        let skill_dir = dir.path().join("skills/passless-agent");
        fs::create_dir_all(&skill_dir).unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, "do not replace").unwrap();
        let path = skill_dir.join("SKILL.md");
        symlink(&outside, &path).unwrap();

        assert!(install_skill(&path, dir.path(), true).is_err());
        assert_eq!(fs::read_to_string(outside).unwrap(), "do not replace");
    }

    #[test]
    fn install_rejects_symlinked_directory_component() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        symlink(outside.path(), dir.path().join("skills")).unwrap();
        let path = dir.path().join("skills/passless-agent/SKILL.md");

        assert!(install_skill(&path, dir.path(), false).is_err());
        assert!(!outside.path().join("passless-agent/SKILL.md").exists());
    }

    #[test]
    fn project_root_uses_git_worktree() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let nested = dir.path().join("a/b");
        fs::create_dir_all(&nested).unwrap();

        assert_eq!(project_root(&nested), dir.path());
    }
}
