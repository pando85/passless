//! Minimal command-line parsing.

use std::path::PathBuf;

use crate::Script;
use crate::server::Config;

pub const USAGE: &str = "usage: notify-double --log <path> [--script <spec>]... \
[--ready-file <path>] [--capabilities a,b,c] [--server-name <name>]\n\
script steps: approve[:ms] | deny[:ms] | ignore | close[:ms] | invoke=<key>[:ms]\n\
env NOTIFY_DOUBLE_SCRIPT: comma-separated steps (used when no --script is given)";

pub struct Cli {
    pub log: PathBuf,
    pub ready_file: Option<PathBuf>,
    pub config: Config,
}

pub fn parse<I>(args: I, env_script: Option<String>) -> Result<Cli, String>
where
    I: IntoIterator<Item = String>,
{
    let mut log = None;
    let mut ready_file = None;
    let mut specs: Vec<String> = Vec::new();
    let mut capabilities = "actions,body,body-markup".to_string();
    let mut server_name = "notify-double".to_string();

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg, None),
        };
        let mut value = |name: &str| {
            inline
                .clone()
                .or_else(|| args.next())
                .ok_or_else(|| format!("{name} requires a value\n{USAGE}"))
        };
        match flag.as_str() {
            "--log" => log = Some(PathBuf::from(value("--log")?)),
            "--ready-file" => ready_file = Some(PathBuf::from(value("--ready-file")?)),
            "--script" => specs.push(value("--script")?),
            "--capabilities" => capabilities = value("--capabilities")?,
            "--server-name" => server_name = value("--server-name")?,
            "-h" | "--help" => return Err(USAGE.to_string()),
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }

    let log = log.ok_or_else(|| format!("--log is required\n{USAGE}"))?;
    let script = if specs.is_empty() {
        match env_script {
            Some(list) => Script::parse_list(&list),
            None => Ok(Script::default()),
        }
    } else {
        Script::parse_specs(specs)
    }
    .map_err(|e| e.to_string())?;

    Ok(Cli {
        log,
        ready_file,
        config: Config {
            script,
            capabilities: capabilities
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            server_name,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn requires_log() {
        assert!(parse(args(&[]), None).is_err());
    }

    #[test]
    fn script_flags_take_precedence_over_env() {
        let cli = parse(
            args(&["--log", "/x", "--script", "deny", "--script=approve:5"]),
            Some("ignore".into()),
        )
        .unwrap();
        assert_eq!(cli.config.script.len(), 2);
        assert_eq!(cli.config.script.step_for(1).unwrap().text(), "approve:5");
    }

    #[test]
    fn env_script_used_when_no_flags() {
        let cli = parse(args(&["--log", "/x"]), Some("deny,approve".into())).unwrap();
        assert_eq!(cli.config.script.len(), 2);
        assert_eq!(cli.config.capabilities, ["actions", "body", "body-markup"]);
    }

    #[test]
    fn bad_script_is_error() {
        assert!(parse(args(&["--log", "/x", "--script", "bogus"]), None).is_err());
    }
}
