//! MCP client configurations that launch their own browser, and their rewrite to the Passless
//! wrapper (`passless agent mcp install`, `passless doctor --agents`).
//!
//! A plain `@playwright/mcp` or `chrome-devtools-mcp` entry starts a browser of its own, so a
//! passkey prompt in it reaches the human's authenticator and the agent profile's rules never
//! apply. This module finds such entries in the configuration of opencode and Claude Code and
//! rewrites each to `passless agent mcp playwright|chrome-devtools --profile P ...`, keeping the
//! entry's name, its other keys, the package pin and the flags that still make sense with an
//! attached browser.
//!
//! The rewrite is a text splice: only the values of `command` and `args` change, every other byte
//! of the file (key order, indentation, other entries, number formatting) stays as it was. That
//! matters for `~/.claude.json`, a large file Claude Code rewrites itself. A file with comments
//! (JSONC) is only analysed, never rewritten.

use std::path::{Path, PathBuf};

use passless_core::{McpAdapterKind, McpInstallClient};

use serde_json::Value;

/// How the entry started its package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runner {
    Npx,
    PnpmDlx,
    Bunx,
    YarnDlx,
    /// A local `playwright-mcp`, `mcp-server-playwright` or `chrome-devtools-mcp` executable.
    Binary,
}

impl Runner {
    pub fn label(self) -> &'static str {
        match self {
            Self::Npx => "npx",
            Self::PnpmDlx => "pnpm dlx",
            Self::Bunx => "bunx",
            Self::YarnDlx => "yarn dlx",
            Self::Binary => "a local executable",
        }
    }
}

/// An entry that starts its own browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainLaunch {
    pub adapter: McpAdapterKind,
    pub runner: Runner,
    /// The absolute path of the `npx` that started the entry; the wrapper keeps it as `--npx`.
    pub npx_path: Option<String>,
    /// The package spec as written (`@playwright/mcp@0.0.83`); `None` for a local executable or a
    /// spec without version.
    pub package: Option<String>,
    /// The arguments the MCP server received.
    pub args: Vec<String>,
    /// Runner options that are not carried over.
    pub runner_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Starts its own browser and can be rewritten.
    Plain(PlainLaunch),
    /// Already runs through `passless agent mcp ...`.
    Wrapped {
        adapter: McpAdapterKind,
        profile: Option<String>,
    },
    /// Starts its own browser, but in a way the installer does not rewrite.
    Unsupported {
        adapter: McpAdapterKind,
        why: String,
    },
    /// Not a browser MCP server.
    Other,
}

const PLAYWRIGHT_PACKAGE: &str = "@playwright/mcp";
const CHROME_DEVTOOLS_PACKAGE: &str = "chrome-devtools-mcp";

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `@playwright/mcp@0.0.83` -> `@playwright/mcp`; `chrome-devtools-mcp@latest` ->
/// `chrome-devtools-mcp`.
fn package_name(spec: &str) -> &str {
    let from = usize::from(spec.starts_with('@'));
    match spec[from..].find('@') {
        Some(at) => &spec[..from + at],
        None => spec,
    }
}

fn package_adapter(spec: &str) -> Option<McpAdapterKind> {
    match package_name(spec) {
        PLAYWRIGHT_PACKAGE => Some(McpAdapterKind::Playwright),
        CHROME_DEVTOOLS_PACKAGE => Some(McpAdapterKind::ChromeDevtools),
        _ => None,
    }
}

/// Tokens that name a browser MCP server wherever they appear (used to tell an unsupported launch
/// from an unrelated server).
fn marker_adapter(token: &str) -> Option<McpAdapterKind> {
    if token.contains("chrome-devtools-mcp") {
        Some(McpAdapterKind::ChromeDevtools)
    } else if ["playwright/mcp", "playwright-mcp", "mcp-server-playwright"]
        .iter()
        .any(|marker| token.contains(marker))
    {
        Some(McpAdapterKind::Playwright)
    } else {
        None
    }
}

fn option_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    let inline = format!("{flag}=");
    argv.iter().enumerate().find_map(|(i, arg)| {
        arg.strip_prefix(&inline)
            .or_else(|| (arg == flag).then(|| argv.get(i + 1).map(String::as_str))?)
    })
}

/// The first argument that is not an option.
fn first_positional(args: &[String]) -> Option<usize> {
    args.iter().position(|arg| !arg.starts_with('-'))
}

/// What an entry's command line starts.
pub fn classify(argv: &[String]) -> Kind {
    let Some(program) = argv.first() else {
        return Kind::Other;
    };
    if let Some(at) = argv.windows(3).position(|w| {
        w[0] == "agent" && w[1] == "mcp" && (w[2] == "playwright" || w[2] == "chrome-devtools")
    }) {
        let adapter = if argv[at + 2] == "playwright" {
            McpAdapterKind::Playwright
        } else {
            McpAdapterKind::ChromeDevtools
        };
        return Kind::Wrapped {
            adapter,
            profile: option_value(&argv[at..], "--profile").map(str::to_owned),
        };
    }
    if argv
        .windows(2)
        .any(|w| w[0] == "agent" && w[1] == "playwright-mcp")
    {
        let profile = option_value(argv, "--profile").map(str::to_owned);
        return Kind::Wrapped {
            adapter: McpAdapterKind::Playwright,
            profile,
        };
    }

    let name = basename(program);
    let direct = match name {
        "playwright-mcp" | "mcp-server-playwright" => Some(McpAdapterKind::Playwright),
        "chrome-devtools-mcp" => Some(McpAdapterKind::ChromeDevtools),
        _ => None,
    };
    if let Some(adapter) = direct {
        return Kind::Plain(PlainLaunch {
            adapter,
            runner: Runner::Binary,
            npx_path: None,
            package: None,
            args: argv[1..].to_vec(),
            runner_notes: Vec::new(),
        });
    }

    let rest = &argv[1..];
    let runner = match name {
        "npx" => Some((Runner::Npx, 1)),
        "pnpx" => Some((Runner::PnpmDlx, 1)),
        "bunx" => Some((Runner::Bunx, 1)),
        "pnpm" | "yarn" | "bun" => {
            let verb = first_positional(rest);
            match (name, verb.map(|i| rest[i].as_str())) {
                ("pnpm", Some("dlx")) => Some((Runner::PnpmDlx, 2 + verb.unwrap_or(0))),
                ("yarn", Some("dlx")) => Some((Runner::YarnDlx, 2 + verb.unwrap_or(0))),
                ("bun", Some("x")) => Some((Runner::Bunx, 2 + verb.unwrap_or(0))),
                _ => None,
            }
        }
        _ => None,
    };
    if let Some((runner, start)) = runner {
        return classify_runner(argv, runner, start, program);
    }

    match argv.iter().find_map(|token| marker_adapter(token)) {
        Some(adapter) => Kind::Unsupported {
            adapter,
            why: format!("it is started through `{name}`, which the installer does not rewrite"),
        },
        None => Kind::Other,
    }
}

/// Runner options that take no value and change nothing the wrapper needs to know.
const QUIET_RUNNER_FLAGS: &[&str] = &[
    "-y",
    "--yes",
    "--no",
    "--no-install",
    "-q",
    "--quiet",
    "-s",
    "--silent",
    "--prefer-online",
    "--prefer-offline",
    "--no-update-notifier",
    "--bun",
];
/// Runner options whose next argument is their value.
const VALUE_RUNNER_FLAGS: &[&str] = &[
    "--registry",
    "--cache",
    "--userconfig",
    "--prefix",
    "--loglevel",
    "-w",
    "--workspace",
    "--node-options",
    "--shell",
];

fn classify_runner(argv: &[String], runner: Runner, start: usize, program: &str) -> Kind {
    let mut notes = Vec::new();
    let mut package_flags: Vec<String> = Vec::new();
    let mut i = start;
    while i < argv.len() && argv[i].starts_with('-') {
        let arg = argv[i].as_str();
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value)),
            None => (arg, None),
        };
        i += 1;
        let mut value = || {
            inline.map(str::to_owned).or_else(|| {
                let next = argv.get(i).cloned();
                i += usize::from(next.is_some());
                next
            })
        };
        match flag {
            "-p" | "--package" => package_flags.extend(value()),
            "-c" | "--call" => {
                let adapter = argv
                    .iter()
                    .find_map(|token| marker_adapter(token))
                    .unwrap_or(McpAdapterKind::Playwright);
                return Kind::Unsupported {
                    adapter,
                    why: format!("it runs a shell command through `{}`", basename(program)),
                };
            }
            f if QUIET_RUNNER_FLAGS.contains(&f) => {}
            f if VALUE_RUNNER_FLAGS.contains(&f) => {
                let _ = value();
                notes.push(format!(
                    "`{flag}` of {} is not carried over",
                    runner.label()
                ));
            }
            _ => notes.push(format!(
                "`{flag}` of {} is not carried over",
                runner.label()
            )),
        }
    }

    let (spec, args_from) = match package_flags
        .iter()
        .find(|spec| package_adapter(spec).is_some())
    {
        // `npx -p @playwright/mcp@x playwright-mcp args`: the first positional names the binary.
        Some(spec) => (spec.clone(), i + usize::from(i < argv.len())),
        None => match argv.get(i) {
            Some(spec) => (spec.clone(), i + 1),
            None => return Kind::Other,
        },
    };
    let Some(adapter) = package_adapter(&spec) else {
        return Kind::Other;
    };
    let npx_path =
        (runner == Runner::Npx && Path::new(program).is_absolute()).then(|| program.to_owned());
    Kind::Plain(PlainLaunch {
        adapter,
        runner,
        npx_path,
        package: (spec != package_name(&spec)).then_some(spec),
        args: argv[args_from.min(argv.len())..].to_vec(),
        runner_notes: notes,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arity {
    None,
    One,
    Many,
}

struct DropRule {
    names: &'static [&'static str],
    arity: Arity,
    why: &'static str,
}

const PLAYWRIGHT_DROPS: &[DropRule] = &[
    DropRule {
        names: &["browser"],
        arity: Arity::One,
        why: "Passless starts the browser and attaches to it",
    },
    DropRule {
        names: &["executable-path"],
        arity: Arity::One,
        why: "Passless starts the browser (set `browser_command` in the profile to choose one)",
    },
    DropRule {
        names: &["user-data-dir"],
        arity: Arity::One,
        why: "the managed browser has a profile directory of its own",
    },
    DropRule {
        names: &["cdp-endpoint"],
        arity: Arity::One,
        why: "Passless supplies the CDP endpoint of the managed browser",
    },
    DropRule {
        names: &["cdp-header", "remote-header"],
        arity: Arity::Many,
        why: "Passless supplies the credentials for its CDP endpoint",
    },
    DropRule {
        names: &["extension", "profile-dir-name"],
        arity: Arity::None,
        why: "attaching to your own browser bypasses Passless",
    },
    DropRule {
        names: &["endpoint"],
        arity: Arity::One,
        why: "a bound browser endpoint bypasses Passless",
    },
    DropRule {
        names: &["device"],
        arity: Arity::One,
        why: "Playwright MCP refuses device emulation with a CDP endpoint",
    },
    DropRule {
        names: &["mobile"],
        arity: Arity::None,
        why: "Playwright MCP refuses device emulation with a CDP endpoint",
    },
    DropRule {
        names: &["no-sandbox", "sandbox"],
        arity: Arity::None,
        why: "the sandbox is a launch option of the browser, which Passless starts",
    },
    DropRule {
        names: &["headless", "headed"],
        arity: Arity::None,
        why: "headed or headless comes from the Passless profile",
    },
    DropRule {
        names: &["port", "host"],
        arity: Arity::One,
        why: "the wrapper needs the stdio transport",
    },
];

const CHROME_DEVTOOLS_DROPS: &[DropRule] = &[
    DropRule {
        names: &["browserurl", "u", "wsendpoint", "w"],
        arity: Arity::One,
        why: "Passless supplies the managed browser's endpoint",
    },
    DropRule {
        names: &["wsheaders"],
        arity: Arity::One,
        why: "Passless supplies the managed browser's endpoint",
    },
    DropRule {
        names: &["autoconnect"],
        arity: Arity::None,
        why: "attaching to your own browser bypasses Passless",
    },
    DropRule {
        names: &["executablepath", "e", "channel"],
        arity: Arity::One,
        why: "Passless starts the browser (set `browser_command` in the profile to choose one)",
    },
    DropRule {
        names: &["userdatadir"],
        arity: Arity::One,
        why: "the managed browser has a profile directory of its own",
    },
    DropRule {
        names: &["headless", "noheadless"],
        arity: Arity::None,
        why: "headed or headless comes from the Passless profile",
    },
    DropRule {
        names: &["isolated", "noisolated"],
        arity: Arity::None,
        why: "it only applies to a browser the server launches",
    },
    DropRule {
        names: &["chromearg", "ignoredefaultchromearg"],
        arity: Arity::Many,
        why: "it only applies to a browser the server launches",
    },
    DropRule {
        names: &["viewport", "proxyserver"],
        arity: Arity::One,
        why: "it only applies to a browser the server launches",
    },
];

/// The flag name of `arg` (without dashes and without `=value`), normalised for matching:
/// chrome-devtools-mcp takes camelCase and kebab-case alike.
fn flag_name(arg: &str, adapter: McpAdapterKind) -> Option<(String, bool)> {
    let body = arg.strip_prefix("--").or_else(|| {
        (adapter == McpAdapterKind::ChromeDevtools)
            .then(|| arg.strip_prefix('-'))
            .flatten()
    })?;
    if body.is_empty() {
        return None;
    }
    let (name, inline) = match body.split_once('=') {
        Some((name, _)) => (name, true),
        None => (body, false),
    };
    let name = match adapter {
        McpAdapterKind::Playwright => name.to_owned(),
        McpAdapterKind::ChromeDevtools => name.replace('-', "").to_lowercase(),
    };
    Some((name, inline))
}

/// The user's arguments minus the flags that conflict with an attached, policy-managed browser,
/// and a note for each dropped flag (the flag, never its value: it may be a credential).
fn filter_args(adapter: McpAdapterKind, args: &[String]) -> (Vec<String>, Vec<String>) {
    let drops = match adapter {
        McpAdapterKind::Playwright => PLAYWRIGHT_DROPS,
        McpAdapterKind::ChromeDevtools => CHROME_DEVTOOLS_DROPS,
    };
    let mut kept = Vec::new();
    let mut notes = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        let rule = flag_name(arg, adapter).and_then(|(name, inline)| {
            drops
                .iter()
                .find(|rule| rule.names.contains(&name.as_str()))
                .map(|rule| (rule, inline))
        });
        let Some((rule, inline)) = rule else {
            kept.push(arg.clone());
            continue;
        };
        if !inline {
            match rule.arity {
                Arity::None => {}
                Arity::One => i += usize::from(i < args.len()),
                Arity::Many => {
                    while i < args.len() && !args[i].starts_with('-') {
                        i += 1;
                    }
                }
            }
        }
        let flag = arg.split_once('=').map_or(arg.as_str(), |(flag, _)| flag);
        notes.push(format!("dropped `{flag}`: {}", rule.why));
    }
    (kept, notes)
}

/// Environment variables of an entry that conflict with the attached browser.
fn env_notes(adapter: McpAdapterKind, env_keys: &[String]) -> Vec<String> {
    const PLAYWRIGHT: &[&str] = &[
        "PLAYWRIGHT_MCP_BROWSER",
        "PLAYWRIGHT_MCP_EXECUTABLE_PATH",
        "PLAYWRIGHT_MCP_USER_DATA_DIR",
        "PLAYWRIGHT_MCP_CDP_ENDPOINT",
        "PLAYWRIGHT_MCP_ENDPOINT",
        "PLAYWRIGHT_MCP_EXTENSION",
        "PLAYWRIGHT_MCP_DEVICE",
        "PLAYWRIGHT_MCP_HEADLESS",
        "PLAYWRIGHT_MCP_NO_SANDBOX",
        "PLAYWRIGHT_MCP_SANDBOX",
    ];
    if adapter != McpAdapterKind::Playwright {
        return Vec::new();
    }
    env_keys
        .iter()
        .filter(|key| PLAYWRIGHT.contains(&key.as_str()))
        .map(|key| {
            format!("environment variable {key} is kept but conflicts with the managed browser: remove it")
        })
        .collect()
}

/// The command line that replaces a plain launch, and what changed on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewrite {
    /// `[passless, agent, mcp, <adapter>, --profile, P, ...]`.
    pub argv: Vec<String>,
    pub notes: Vec<String>,
}

pub fn rewrite(
    launch: &PlainLaunch,
    passless: &str,
    profile: &str,
    env_keys: &[String],
    with_access_tool: bool,
) -> Rewrite {
    let adapter_name = match launch.adapter {
        McpAdapterKind::Playwright => "playwright",
        McpAdapterKind::ChromeDevtools => "chrome-devtools",
    };
    let mut argv: Vec<String> = [passless, "agent", "mcp", adapter_name, "--profile", profile]
        .map(str::to_owned)
        .to_vec();
    let mut notes = launch.runner_notes.clone();
    match launch.runner {
        Runner::Npx => {}
        Runner::Binary => notes.push(format!(
            "{} is replaced by `npx {}` (the wrapper runs the package with npx; pass `--package <spec>` to pin a version)",
            launch.runner.label(),
            match launch.adapter {
                McpAdapterKind::Playwright => PLAYWRIGHT_PACKAGE,
                McpAdapterKind::ChromeDevtools => CHROME_DEVTOOLS_PACKAGE,
            }
        )),
        runner => notes.push(format!(
            "{} is replaced by npx with the same package spec (the wrapper runs `npx --yes <package>`)",
            runner.label()
        )),
    }
    if let Some(npx) = &launch.npx_path {
        argv.extend(["--npx".to_owned(), npx.clone()]);
    }
    // Only the Playwright wrapper has the tool (ADR 0014 amendment section 6).
    if with_access_tool && launch.adapter == McpAdapterKind::Playwright {
        argv.push("--with-access-tool".to_owned());
    }
    if let Some(package) = &launch.package {
        argv.extend(["--package".to_owned(), package.clone()]);
    }
    let (kept, dropped) = filter_args(launch.adapter, &launch.args);
    notes.extend(dropped);
    notes.extend(env_notes(launch.adapter, env_keys));
    if launch.adapter == McpAdapterKind::Playwright
        && kept
            .iter()
            .any(|arg| arg == "--config" || arg.starts_with("--config="))
    {
        notes.push(
            "`--config` is kept: check that its file sets no browser, executablePath or userDataDir"
                .to_owned(),
        );
    }
    if !kept.is_empty() {
        argv.push("--".to_owned());
        argv.extend(kept);
    }
    Rewrite { argv, notes }
}

// ---------------------------------------------------------------------------------------------
// Client configuration files
// ---------------------------------------------------------------------------------------------

/// Where a client's MCP entries live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRef {
    pub name: String,
    /// The key path to the entry object, e.g. `["mcp", "servers", "playwright"]`.
    pub path: Vec<String>,
}

impl EntryRef {
    pub fn location(&self) -> String {
        match self.path.as_slice() {
            // A Claude Code local-scope entry: `projects[<abs path>].mcpServers.<name>`.
            [projects, project, servers, name] if projects == "projects" => {
                format!("{projects}[{project}].{servers}.{name}")
            }
            _ => self.path.join("."),
        }
    }

    /// The project directory of a Claude Code local-scope entry (`claude mcp add` without
    /// `--scope`, kept under `projects.<abs path>.mcpServers` of the user-level file).
    pub fn local_project(&self) -> Option<&str> {
        match self.path.as_slice() {
            [projects, project, _, _] if projects == "projects" => Some(project),
            _ => None,
        }
    }
}

/// An entry of a configuration file.
#[derive(Debug, Clone)]
pub struct FoundEntry {
    pub entry: EntryRef,
    pub argv: Vec<String>,
    pub env_keys: Vec<String>,
    pub kind: Kind,
}

fn string_list(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn env_keys_of(entry: &Value, key: &str) -> Vec<String> {
    entry
        .get(key)
        .and_then(Value::as_object)
        .map(|env| env.keys().cloned().collect())
        .unwrap_or_default()
}

/// The entries of `root` that launch a command: opencode `mcp.servers.<name>` (and the legacy
/// `mcp.<name>`, which its schema marks deprecated), Claude Code `mcpServers.<name>` and, in the
/// user-level file, the local-scope `projects.<abs path>.mcpServers.<name>`.
pub fn find_entries(client: McpInstallClient, root: &Value) -> Vec<FoundEntry> {
    let mut found = Vec::new();
    let mut add = |path: Vec<String>, entry: &Value| {
        let (argv, env_key) = match client {
            McpInstallClient::Opencode => {
                if entry
                    .get("type")
                    .is_some_and(|t| t.as_str() != Some("local"))
                {
                    return;
                }
                match entry.get("command").and_then(string_list) {
                    Some(argv) => (argv, "environment"),
                    None => return,
                }
            }
            McpInstallClient::ClaudeCode => {
                if entry
                    .get("type")
                    .is_some_and(|t| t.as_str() != Some("stdio"))
                {
                    return;
                }
                let Some(command) = entry.get("command").and_then(Value::as_str) else {
                    return;
                };
                let mut argv = vec![command.to_owned()];
                match entry.get("args") {
                    None => {}
                    Some(args) => match string_list(args) {
                        Some(args) => argv.extend(args),
                        None => return,
                    },
                }
                (argv, "env")
            }
        };
        let kind = classify(&argv);
        if kind == Kind::Other {
            return;
        }
        found.push(FoundEntry {
            entry: EntryRef {
                name: path.last().cloned().unwrap_or_default(),
                path,
            },
            env_keys: env_keys_of(entry, env_key),
            argv,
            kind,
        });
    };
    match client {
        McpInstallClient::Opencode => {
            if let Some(mcp) = root.get("mcp").and_then(Value::as_object) {
                for (name, entry) in mcp {
                    if name == "servers" {
                        if let Some(servers) = entry.as_object() {
                            for (name, entry) in servers {
                                add(vec!["mcp".into(), "servers".into(), name.clone()], entry);
                            }
                        }
                    } else if name != "timeout" {
                        add(vec!["mcp".into(), name.clone()], entry);
                    }
                }
            }
        }
        McpInstallClient::ClaudeCode => {
            if let Some(servers) = root.get("mcpServers").and_then(Value::as_object) {
                for (name, entry) in servers {
                    add(vec!["mcpServers".into(), name.clone()], entry);
                }
            }
            if let Some(projects) = root.get("projects").and_then(Value::as_object) {
                for (project, config) in projects {
                    let Some(servers) = config.get("mcpServers").and_then(Value::as_object) else {
                        continue;
                    };
                    for (name, entry) in servers {
                        add(
                            vec![
                                "projects".into(),
                                project.clone(),
                                "mcpServers".into(),
                                name.clone(),
                            ],
                            entry,
                        );
                    }
                }
            }
        }
    }
    found
}

/// The entry with a new command line, in the client's format.
pub fn entry_with_argv(client: McpInstallClient, entry: &Value, argv: &[String]) -> Value {
    let mut entry = entry.clone();
    if let Some(object) = entry.as_object_mut() {
        match client {
            McpInstallClient::Opencode => {
                object.insert("command".into(), argv.into());
            }
            McpInstallClient::ClaudeCode => {
                object.insert("command".into(), argv[0].clone().into());
                object.insert("args".into(), argv[1..].into());
            }
        }
    }
    entry
}

/// What happened to one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Rewritten {
        runner: String,
        adapter: McpAdapterKind,
        argv: Vec<String>,
        notes: Vec<String>,
        /// The whole new entry, for a file that cannot be edited in place.
        snippet: String,
    },
    AlreadyWrapped {
        adapter: McpAdapterKind,
        profile: Option<String>,
    },
    Unsupported {
        adapter: McpAdapterKind,
        why: String,
        /// A wrapper entry to adapt by hand.
        snippet: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPlan {
    pub entry: EntryRef,
    pub outcome: Outcome,
}

/// The analysis of one configuration file.
#[derive(Debug, Clone)]
pub struct Plan {
    pub entries: Vec<EntryPlan>,
    /// The file contains comments or trailing commas: it was analysed but cannot be rewritten
    /// without losing them.
    pub jsonc: bool,
    /// The new file content; `None` when nothing changes or the file is JSONC.
    pub new_text: Option<String>,
}

impl Plan {
    /// Whether the file has a browser MCP entry at its own level: not one of the Claude Code
    /// local-scope entries of other projects, which are rewritten but do not make a user-level
    /// install redundant.
    pub fn has_scope_level_entry(&self) -> bool {
        self.entries
            .iter()
            .any(|plan| plan.entry.local_project().is_none())
    }

    pub fn rewritten(&self) -> impl Iterator<Item = &EntryPlan> {
        self.entries
            .iter()
            .filter(|plan| matches!(plan.outcome, Outcome::Rewritten { .. }))
    }
}

#[derive(Debug)]
pub enum PlanError {
    /// The file is not JSON (and not JSONC either).
    Invalid(String),
    /// The rewrite did not verify; nothing was changed.
    Internal(String),
    /// The change is refused (a server of that name is not ours, the file has an unexpected
    /// shape); nothing was changed.
    Refused(String),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(why) => write!(f, "not valid JSON: {why}"),
            Self::Internal(why) => write!(f, "internal error, nothing was changed: {why}"),
            Self::Refused(why) => write!(f, "{why}"),
        }
    }
}

/// Parse `text`; a file with comments or trailing commas parses as JSONC (`true`).
pub fn parse_config(text: &str) -> Result<(Value, bool), PlanError> {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => Ok((value, false)),
        Err(strict) => match serde_json::from_str::<Value>(&strip_jsonc(text)) {
            Ok(value) => Ok((value, true)),
            Err(_) => Err(PlanError::Invalid(strict.to_string())),
        },
    }
}

/// `text` without `//` and `/* */` comments and without trailing commas.
pub fn strip_jsonc(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let byte = bytes[i];
        if in_string {
            out.push(byte);
            if byte == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1]);
                i += 1;
            } else if byte == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match (byte, bytes.get(i + 1)) {
            (b'"', _) => {
                in_string = true;
                out.push(byte);
                i += 1;
            }
            (b'/', Some(b'/')) => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
                i += 2;
            }
            _ => {
                out.push(byte);
                i += 1;
            }
        }
    }
    // Trailing commas.
    let mut result: Vec<u8> = Vec::with_capacity(out.len());
    let mut in_string = false;
    let mut i = 0;
    while i < out.len() {
        let byte = out[i];
        if in_string {
            result.push(byte);
            if byte == b'\\' && i + 1 < out.len() {
                result.push(out[i + 1]);
                i += 1;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
            result.push(byte);
        } else if byte == b',' {
            let next = out[i + 1..]
                .iter()
                .find(|b| !b.is_ascii_whitespace())
                .copied();
            if !matches!(next, Some(b'}' | b']')) {
                result.push(byte);
            }
        } else {
            result.push(byte);
        }
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

/// A wrapper entry, for an entry the installer cannot rewrite.
fn generic_snippet(
    client: McpInstallClient,
    entry: &EntryRef,
    adapter: McpAdapterKind,
    passless: &str,
    profile: &str,
    with_access_tool: bool,
) -> String {
    let adapter_name = match adapter {
        McpAdapterKind::Playwright => "playwright",
        McpAdapterKind::ChromeDevtools => "chrome-devtools",
    };
    let mut argv: Vec<String> = [passless, "agent", "mcp", adapter_name, "--profile", profile]
        .map(str::to_owned)
        .to_vec();
    if with_access_tool && adapter == McpAdapterKind::Playwright {
        argv.push("--with-access-tool".to_owned());
    }
    entry_snippet(
        client,
        entry,
        &entry_with_argv(client, &Value::Object(Default::default()), &argv),
    )
}

fn entry_snippet(client: McpInstallClient, entry: &EntryRef, value: &Value) -> String {
    let mut object = serde_json::Map::new();
    let mut value = value.clone();
    if client == McpInstallClient::ClaudeCode
        && let Some(map) = value.as_object_mut()
    {
        map.entry("type").or_insert_with(|| "stdio".into());
    }
    if client == McpInstallClient::Opencode
        && let Some(map) = value.as_object_mut()
    {
        map.entry("type").or_insert_with(|| "local".into());
    }
    object.insert(entry.name.clone(), value);
    serde_json::to_string_pretty(&Value::Object(object)).unwrap_or_default()
}

/// Analyse `text` and, for a file that can be edited in place, produce its new content.
pub fn plan(
    client: McpInstallClient,
    text: &str,
    passless: &str,
    profile: &str,
    with_access_tool: bool,
) -> Result<Plan, PlanError> {
    let (root, jsonc) = parse_config(text)?;
    let mut entries = Vec::new();
    let mut edits: Vec<(Vec<String>, Vec<String>)> = Vec::new();
    for found in find_entries(client, &root) {
        let outcome = match &found.kind {
            Kind::Other => continue,
            Kind::Wrapped { adapter, profile } => Outcome::AlreadyWrapped {
                adapter: *adapter,
                profile: profile.clone(),
            },
            Kind::Unsupported { adapter, why } => Outcome::Unsupported {
                adapter: *adapter,
                why: why.clone(),
                snippet: generic_snippet(
                    client,
                    &found.entry,
                    *adapter,
                    passless,
                    profile,
                    with_access_tool,
                ),
            },
            Kind::Plain(launch) => {
                let rewritten =
                    rewrite(launch, passless, profile, &found.env_keys, with_access_tool);
                let original = entry_value(&root, &found.entry.path);
                let snippet = entry_snippet(
                    client,
                    &found.entry,
                    &entry_with_argv(client, &original, &rewritten.argv),
                );
                edits.push((found.entry.path.clone(), rewritten.argv.clone()));
                Outcome::Rewritten {
                    runner: launch.runner.label().to_owned(),
                    adapter: launch.adapter,
                    argv: rewritten.argv,
                    notes: rewritten.notes,
                    snippet,
                }
            }
        };
        entries.push(EntryPlan {
            entry: found.entry,
            outcome,
        });
    }
    if jsonc || edits.is_empty() {
        return Ok(Plan {
            entries,
            jsonc,
            new_text: None,
        });
    }
    let new_text = apply_edits(client, text, &edits)?;
    // The result must parse and every rewritten entry must now read as wrapped.
    let (check, _) = parse_config(&new_text)
        .map_err(|e| PlanError::Internal(format!("the new file does not parse: {e}")))?;
    let after = find_entries(client, &check);
    for (path, argv) in &edits {
        let ok = after.iter().any(|entry| {
            &entry.entry.path == path
                && &entry.argv == argv
                && matches!(entry.kind, Kind::Wrapped { .. })
        });
        if !ok {
            return Err(PlanError::Internal(format!(
                "entry {} did not read back as rewritten",
                path.join(".")
            )));
        }
    }
    Ok(Plan {
        entries,
        jsonc,
        new_text: Some(new_text),
    })
}

fn entry_value(root: &Value, path: &[String]) -> Value {
    path.iter()
        .try_fold(root, |value, key| value.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------------------------
// Splicing into the original text
// ---------------------------------------------------------------------------------------------

/// Byte offsets of a value, from its first to one past its last byte.
type Span = (usize, usize);

struct Member {
    key: String,
    key_start: usize,
    value: Span,
}

/// A scanner over valid JSON text (callers parse it with serde_json first).
struct Scanner<'a> {
    src: &'a [u8],
}

impl Scanner<'_> {
    fn skip_ws(&self, mut i: usize) -> usize {
        while i < self.src.len() && self.src[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    }

    fn string_end(&self, start: usize) -> Option<usize> {
        let mut i = start + 1;
        while i < self.src.len() {
            match self.src[i] {
                b'\\' => i += 2,
                b'"' => return Some(i + 1),
                _ => i += 1,
            }
        }
        None
    }

    fn value_end(&self, start: usize, depth: usize) -> Option<usize> {
        if depth > 64 {
            return None;
        }
        match *self.src.get(start)? {
            b'"' => self.string_end(start),
            b'{' => self.members(start, depth + 1).map(|(_, end)| end),
            b'[' => self.items(start, depth + 1).map(|(_, end)| end),
            _ => {
                let mut i = start;
                while i < self.src.len()
                    && !matches!(self.src[i], b',' | b']' | b'}')
                    && !self.src[i].is_ascii_whitespace()
                {
                    i += 1;
                }
                Some(i)
            }
        }
    }

    /// The members of the object at `start`, and its end.
    fn members(&self, start: usize, depth: usize) -> Option<(Vec<Member>, usize)> {
        let mut members = Vec::new();
        let mut i = self.skip_ws(start + 1);
        loop {
            match *self.src.get(i)? {
                b'}' => return Some((members, i + 1)),
                b',' => i = self.skip_ws(i + 1),
                b'"' => {
                    let key_end = self.string_end(i)?;
                    let key = serde_json::from_slice::<String>(&self.src[i..key_end]).ok()?;
                    let colon = self.skip_ws(key_end);
                    if *self.src.get(colon)? != b':' {
                        return None;
                    }
                    let value_start = self.skip_ws(colon + 1);
                    let value_end = self.value_end(value_start, depth)?;
                    members.push(Member {
                        key,
                        key_start: i,
                        value: (value_start, value_end),
                    });
                    i = self.skip_ws(value_end);
                }
                _ => return None,
            }
        }
    }

    /// The items of the array at `start`, and its end.
    fn items(&self, start: usize, depth: usize) -> Option<(Vec<Span>, usize)> {
        let mut items = Vec::new();
        let mut i = self.skip_ws(start + 1);
        loop {
            match *self.src.get(i)? {
                b']' => return Some((items, i + 1)),
                b',' => i = self.skip_ws(i + 1),
                _ => {
                    let end = self.value_end(i, depth)?;
                    items.push((i, end));
                    i = self.skip_ws(end);
                }
            }
        }
    }

    /// The object at the end of `path` (the last of duplicate keys wins, as in serde_json).
    fn locate(&self, path: &[String]) -> Option<Span> {
        let mut span = (self.skip_ws(0), 0);
        span.1 = self.value_end(span.0, 0)?;
        for key in path {
            if self.src.get(span.0) != Some(&b'{') {
                return None;
            }
            let (members, _) = self.members(span.0, 0)?;
            span = members.into_iter().rfind(|m| &m.key == key)?.value;
        }
        Some(span)
    }
}

/// The indentation of the line `pos` starts, `None` when something else precedes it on the line.
fn line_indent(src: &str, pos: usize) -> Option<&str> {
    let line_start = src[..pos].rfind('\n').map_or(0, |at| at + 1);
    let indent = &src[line_start..pos];
    indent
        .chars()
        .all(|c| c == ' ' || c == '\t')
        .then_some(indent)
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

/// A string array, in the layout of the array it replaces (one item per line when that was
/// multi-line, inline otherwise).
fn render_array(
    src: &str,
    existing: Option<Span>,
    key_indent: Option<&str>,
    items: &[String],
) -> String {
    let encoded: Vec<String> = items.iter().map(|item| json_string(item)).collect();
    let multiline = match existing {
        Some((start, end)) => src[start..end].contains('\n'),
        None => key_indent.is_some(),
    };
    if !multiline {
        return format!("[{}]", encoded.join(", "));
    }
    let closing = key_indent.unwrap_or("");
    let item_indent = existing
        .and_then(|(start, end)| {
            Scanner {
                src: src.as_bytes(),
            }
            .items(start, 0)
            .and_then(|(items, _)| items.first().copied())
            .filter(|&(first, _)| first < end)
            .and_then(|(first, _)| line_indent(src, first))
        })
        .map_or_else(|| format!("{closing}  "), str::to_owned);
    let body: Vec<String> = encoded
        .iter()
        .map(|item| format!("{item_indent}{item}"))
        .collect();
    format!("[\n{}\n{closing}]", body.join(",\n"))
}

/// Replace the command (and arguments) of every listed entry.
fn apply_edits(
    client: McpInstallClient,
    text: &str,
    edits: &[(Vec<String>, Vec<String>)],
) -> Result<String, PlanError> {
    let scanner = Scanner {
        src: text.as_bytes(),
    };
    let missing = |what: &str, path: &[String]| {
        PlanError::Internal(format!("cannot locate {what} of {}", path.join(".")))
    };
    // (start, end, replacement); applied from the back so earlier offsets stay valid.
    let mut splices: Vec<(usize, usize, String)> = Vec::new();
    for (path, argv) in edits {
        let entry = scanner
            .locate(path)
            .ok_or_else(|| missing("the entry", path))?;
        let (members, _) = scanner
            .members(entry.0, 0)
            .ok_or_else(|| missing("the members", path))?;
        let member = |key: &str| members.iter().rfind(|m| m.key == key);
        let command = member("command").ok_or_else(|| missing("command", path))?;
        let key_indent = line_indent(text, command.key_start);
        match client {
            McpInstallClient::Opencode => {
                let (start, end) = command.value;
                splices.push((
                    start,
                    end,
                    render_array(text, Some(command.value), key_indent, argv),
                ));
            }
            McpInstallClient::ClaudeCode => {
                let (start, end) = command.value;
                let mut args_splice = None;
                match member("args") {
                    Some(args) => {
                        let (a_start, a_end) = args.value;
                        let args_indent = line_indent(text, args.key_start);
                        args_splice = Some((
                            a_start,
                            a_end,
                            render_array(text, Some(args.value), args_indent, &argv[1..]),
                        ));
                    }
                    None => {
                        let array = render_array(text, None, key_indent, &argv[1..]);
                        let insert = match key_indent {
                            Some(indent) => format!(",\n{indent}\"args\": {array}"),
                            None => format!(", \"args\": {array}"),
                        };
                        splices.push((end, end, insert));
                    }
                }
                splices.push((start, end, json_string(&argv[0])));
                splices.extend(args_splice);
            }
        }
    }
    splices.sort_by_key(|&(start, _, _)| std::cmp::Reverse(start));
    let mut out = text.to_owned();
    for (start, end, replacement) in splices {
        out.replace_range(start..end, &replacement);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Adding an entry
// ---------------------------------------------------------------------------------------------

/// The name of the server `agent mcp install` adds when a file has no browser MCP entry. It is the
/// name Playwright MCP's own documentation uses, so the tools stay `mcp__playwright__*` in Claude
/// Code and the entry is the same one `agent mcp --print-config` prints.
pub const NEW_ENTRY_NAME: &str = "playwright";

/// A small JSON tree with a fixed key order, rendered in the layout of the file it goes into
/// (`serde_json` maps do not keep the order the entries are built in).
enum Node {
    Str(String),
    List(Vec<String>),
    Obj(Vec<(String, Node)>),
}

impl Node {
    fn render(&self, unit: &str, base: &str, multiline: bool) -> String {
        let inner = format!("{base}{unit}");
        match self {
            Node::Str(text) => json_string(text),
            Node::List(items) if items.is_empty() => "[]".to_owned(),
            Node::List(items) => {
                let items: Vec<String> = items.iter().map(|item| json_string(item)).collect();
                if multiline {
                    let body: Vec<String> =
                        items.iter().map(|item| format!("{inner}{item}")).collect();
                    format!("[\n{}\n{base}]", body.join(",\n"))
                } else {
                    format!("[{}]", items.join(", "))
                }
            }
            Node::Obj(members) => {
                let members: Vec<String> = members
                    .iter()
                    .map(|(key, node)| {
                        format!(
                            "{}: {}",
                            json_string(key),
                            node.render(unit, &inner, multiline)
                        )
                    })
                    .collect();
                if multiline {
                    let body: Vec<String> = members
                        .iter()
                        .map(|member| format!("{inner}{member}"))
                        .collect();
                    format!("{{\n{}\n{base}}}", body.join(",\n"))
                } else {
                    format!("{{{}}}", members.join(", "))
                }
            }
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Node::Str(text) => Value::String(text.clone()),
            Node::List(items) => items.clone().into(),
            Node::Obj(members) => Value::Object(
                members
                    .iter()
                    .map(|(key, node)| (key.clone(), node.to_value()))
                    .collect(),
            ),
        }
    }
}

/// `keys` wrapped around `leaf`: `["a", "b"]` gives `{"a": {"b": leaf}}`.
fn nest(keys: &[String], leaf: Node) -> Node {
    keys.iter()
        .rev()
        .fold(leaf, |node, key| Node::Obj(vec![(key.clone(), node)]))
}

/// Where a new entry goes: the layout the existing rewrite and `--print-config` use.
fn new_entry_path(client: McpInstallClient) -> Vec<String> {
    let path: &[&str] = match client {
        McpInstallClient::Opencode => &["mcp", "servers", NEW_ENTRY_NAME],
        McpInstallClient::ClaudeCode => &["mcpServers", NEW_ENTRY_NAME],
    };
    path.iter().map(|key| (*key).to_owned()).collect()
}

fn new_entry_node(client: McpInstallClient, argv: &[String]) -> Node {
    match client {
        McpInstallClient::Opencode => Node::Obj(vec![
            ("type".into(), Node::Str("local".into())),
            ("command".into(), Node::List(argv.to_vec())),
        ]),
        McpInstallClient::ClaudeCode => Node::Obj(vec![
            ("type".into(), Node::Str("stdio".into())),
            ("command".into(), Node::Str(argv[0].clone())),
            ("args".into(), Node::List(argv[1..].to_vec())),
        ]),
    }
}

/// A new `playwright` entry for a file that has no browser MCP entry.
#[derive(Debug, Clone)]
pub struct AddPlan {
    pub entry: EntryRef,
    /// `[passless, agent, mcp, playwright, --profile, P]`: the command line a rewrite of a plain
    /// `npx @playwright/mcp` produces, without a pin or flags to carry over.
    pub argv: Vec<String>,
    /// The file already has comments or trailing commas: it is not edited.
    pub jsonc: bool,
    /// The new file content (the whole file when `text` was `None`); `None` for a JSONC file.
    pub new_text: Option<String>,
    /// The entry on its own, for a file that is not edited.
    pub snippet: String,
}

/// The indentation of the line `pos` is on.
fn leading_indent(src: &str, pos: usize) -> &str {
    let line_start = src[..pos].rfind('\n').map_or(0, |at| at + 1);
    let rest = &src[line_start..];
    let width = rest
        .find(|c: char| c != ' ' && c != '\t')
        .unwrap_or(rest.len());
    &rest[..width]
}

/// What an existing server of the reserved name is, for the refusal.
fn describe_existing(entry: &Value) -> String {
    let command = match entry.get("command") {
        Some(Value::String(command)) => Some(command.clone()),
        Some(Value::Array(argv)) => Some(
            argv.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => None,
    };
    match (command, entry.get("url").and_then(Value::as_str)) {
        (Some(command), _) => format!("it runs `{command}`"),
        (None, Some(url)) => format!("it connects to {url}"),
        _ => "it is not a command that starts a Playwright MCP server".to_owned(),
    }
}

/// Plan a new `playwright` entry. `text` is the file, or `None` when it does not exist (the plan
/// then holds the content of the new file). The caller has established that the file has no
/// browser MCP entry ([`plan`] found none): this refuses when another server already uses the
/// name.
///
/// Like the rewrite, the edit is a text splice: only the new member is inserted, in the layout of
/// its neighbours, and every other byte of the file stays as it was.
pub fn plan_add(
    client: McpInstallClient,
    text: Option<&str>,
    passless: &str,
    profile: &str,
    with_access_tool: bool,
) -> Result<AddPlan, PlanError> {
    let launch = PlainLaunch {
        adapter: McpAdapterKind::Playwright,
        runner: Runner::Npx,
        npx_path: None,
        package: None,
        args: Vec::new(),
        runner_notes: Vec::new(),
    };
    let argv = rewrite(&launch, passless, profile, &[], with_access_tool).argv;
    let path = new_entry_path(client);
    let entry = EntryRef {
        name: NEW_ENTRY_NAME.to_owned(),
        path: path.clone(),
    };
    let node = new_entry_node(client, &argv);
    let snippet = entry_snippet(
        client,
        &entry,
        &entry_with_argv(client, &Value::Object(Default::default()), &argv),
    );
    let done = |jsonc: bool, new_text: Option<String>| AddPlan {
        entry: entry.clone(),
        argv: argv.clone(),
        jsonc,
        new_text,
        snippet: snippet.clone(),
    };

    let Some(text) = text else {
        let mut members = Vec::new();
        if client == McpInstallClient::Opencode {
            members.push((
                "$schema".to_owned(),
                Node::Str("https://opencode.ai/config.json".to_owned()),
            ));
        }
        members.push((path[0].clone(), nest(&path[1..], node)));
        let content = Node::Obj(members).render("  ", "", true) + "\n";
        return Ok(done(false, Some(content)));
    };

    let (root, jsonc) = parse_config(text)?;
    if !root.is_object() {
        return Err(PlanError::Refused(
            "the top level of the file is not a JSON object".to_owned(),
        ));
    }
    // A server of that name that is not one of ours: never replaced. (`mcp.playwright` is the
    // legacy opencode spelling of `mcp.servers.playwright`.)
    let mut names = vec![path.clone()];
    if client == McpInstallClient::Opencode {
        names.push(vec!["mcp".to_owned(), NEW_ENTRY_NAME.to_owned()]);
    }
    for name in &names {
        if let Some(existing) = root_value(&root, name) {
            return Err(PlanError::Refused(format!(
                "a server named `{NEW_ENTRY_NAME}` ({}) already exists and is not a Playwright MCP \
                 server ({}): refusing to replace it. Rename or remove it first, then run the \
                 command again",
                name.join("."),
                describe_existing(existing)
            )));
        }
    }
    if jsonc {
        return Ok(done(true, None));
    }

    let scanner = Scanner {
        src: text.as_bytes(),
    };
    // The deepest existing object on the way to the entry; the missing keys below it are nested
    // around the entry.
    let mut object = (
        scanner.skip_ws(0),
        scanner
            .value_end(scanner.skip_ws(0), 0)
            .ok_or_else(|| PlanError::Internal("cannot scan the file".to_owned()))?,
    );
    let mut depth = 0;
    while depth < path.len() - 1 {
        let (members, _) = scanner
            .members(object.0, 0)
            .ok_or_else(|| PlanError::Internal("cannot scan the file".to_owned()))?;
        match members.into_iter().rfind(|m| m.key == path[depth]) {
            Some(member) => {
                if text.as_bytes().get(member.value.0) != Some(&b'{') {
                    return Err(PlanError::Refused(format!(
                        "`{}` is not a JSON object: refusing to change it",
                        path[..=depth].join(".")
                    )));
                }
                object = member.value;
                depth += 1;
            }
            None => break,
        }
    }
    let key = &path[depth];
    let value = nest(&path[depth + 1..], node);

    let (members, end) = scanner
        .members(object.0, 0)
        .ok_or_else(|| PlanError::Internal("cannot scan the file".to_owned()))?;
    let root_start = scanner.skip_ws(0);
    let root_end = scanner.value_end(root_start, 0).unwrap_or(text.len());
    let multiline = text[root_start..root_end].contains('\n');
    // One level of indentation of this file: the indent of the first top-level member.
    let unit = scanner
        .members(root_start, 0)
        .and_then(|(top, _)| {
            top.iter()
                .find_map(|m| line_indent(text, m.key_start).filter(|i| !i.is_empty()))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "  ".to_owned());
    let key_text = json_string(key);
    let mut out = text.to_owned();
    match members.last() {
        Some(last) => match line_indent(text, last.key_start) {
            Some(indent) => out.insert_str(
                last.value.1,
                &format!(
                    ",\n{indent}{key_text}: {}",
                    value.render(&unit, indent, true)
                ),
            ),
            None => out.insert_str(
                last.value.1,
                &format!(", {key_text}: {}", value.render(&unit, "", false)),
            ),
        },
        // An empty top-level object (`{}`) is always spread out: nobody wants a compact config.
        None if multiline || object.0 == root_start => {
            let parent = leading_indent(text, object.0);
            let inner = format!("{parent}{unit}");
            out.replace_range(
                object.0..end,
                &format!(
                    "{{\n{inner}{key_text}: {}\n{parent}}}",
                    value.render(&unit, &inner, true)
                ),
            );
        }
        None => out.replace_range(
            object.0..end,
            &format!("{{{key_text}: {}}}", value.render(&unit, "", false)),
        ),
    }

    // The result must parse, hold exactly the old content plus the new entry, and read back as
    // a Passless entry.
    let (check, _) = parse_config(&out)
        .map_err(|e| PlanError::Internal(format!("the new file does not parse: {e}")))?;
    let mut expected = root.clone();
    let mut cursor = &mut expected;
    for (i, step) in path.iter().enumerate() {
        let Some(map) = cursor.as_object_mut() else {
            return Err(PlanError::Internal("the file changed shape".to_owned()));
        };
        cursor = if i + 1 == path.len() {
            map.entry(step.clone())
                .or_insert_with(|| new_entry_node(client, &argv).to_value())
        } else {
            map.entry(step.clone())
                .or_insert_with(|| Value::Object(Default::default()))
        };
    }
    if check != expected {
        return Err(PlanError::Internal(
            "the new file differs from the old one by more than the new entry".to_owned(),
        ));
    }
    let wrapped = find_entries(client, &check).into_iter().any(|found| {
        found.entry.path == path && found.argv == argv && matches!(found.kind, Kind::Wrapped { .. })
    });
    if !wrapped {
        return Err(PlanError::Internal(
            "the new entry did not read back as a Passless entry".to_owned(),
        ));
    }
    Ok(done(false, Some(out)))
}

/// The value at `path` of `root`, if there is one.
fn root_value<'a>(root: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(root, |value, key| value.get(key))
}

// ---------------------------------------------------------------------------------------------
// Unified diff
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Keep,
    Del,
    Add,
}

/// A unified diff of `old` and `new` (3 lines of context); empty when they are equal.
pub fn unified_diff(label: &str, old: &str, new: &str) -> String {
    if old == new {
        return String::new();
    }
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (ma, mb) = (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix]);

    // The middle, by longest common subsequence (the changed region is small for a config file;
    // beyond a bound the middle is replaced as a whole).
    let mut ops: Vec<Op> = vec![Op::Keep; prefix];
    if ma.len().saturating_mul(mb.len()) <= 16_000_000 {
        let width = mb.len() + 1;
        let mut table = vec![0u32; (ma.len() + 1) * width];
        for i in (0..ma.len()).rev() {
            for j in (0..mb.len()).rev() {
                table[i * width + j] = if ma[i] == mb[j] {
                    table[(i + 1) * width + j + 1] + 1
                } else {
                    table[(i + 1) * width + j].max(table[i * width + j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < ma.len() || j < mb.len() {
            if i < ma.len() && j < mb.len() && ma[i] == mb[j] {
                ops.push(Op::Keep);
                i += 1;
                j += 1;
            } else if i < ma.len()
                && (j == mb.len() || table[(i + 1) * width + j] >= table[i * width + j + 1])
            {
                ops.push(Op::Del);
                i += 1;
            } else {
                ops.push(Op::Add);
                j += 1;
            }
        }
    } else {
        ops.extend(std::iter::repeat_n(Op::Del, ma.len()));
        ops.extend(std::iter::repeat_n(Op::Add, mb.len()));
    }
    ops.extend(std::iter::repeat_n(Op::Keep, suffix));

    // Line numbers (0-based) of each op in a and b.
    let mut positions = Vec::with_capacity(ops.len());
    let (mut ai, mut bi) = (0usize, 0usize);
    for op in &ops {
        positions.push((ai, bi));
        match op {
            Op::Keep => {
                ai += 1;
                bi += 1;
            }
            Op::Del => ai += 1,
            Op::Add => bi += 1,
        }
    }

    const CONTEXT: usize = 3;
    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| **op != Op::Keep)
        .map(|(i, _)| i)
        .collect();
    let mut out = format!("--- a/{label}\n+++ b/{label}\n");
    let mut idx = 0;
    while idx < changed.len() {
        let mut first = changed[idx];
        let mut last = changed[idx];
        while idx + 1 < changed.len() && changed[idx + 1] - last <= 2 * CONTEXT {
            idx += 1;
            last = changed[idx];
        }
        idx += 1;
        first = first.saturating_sub(CONTEXT);
        let end = (last + CONTEXT + 1).min(ops.len());
        let (a_start, b_start) = positions[first];
        let a_count = ops[first..end].iter().filter(|op| **op != Op::Add).count();
        let b_count = ops[first..end].iter().filter(|op| **op != Op::Del).count();
        let fmt_range = |start: usize, count: usize| {
            if count == 1 {
                format!("{}", start + 1)
            } else {
                format!("{},{}", start + usize::from(count > 0), count)
            }
        };
        out.push_str(&format!(
            "@@ -{} +{} @@\n",
            fmt_range(a_start, a_count),
            fmt_range(b_start, b_count)
        ));
        for k in first..end {
            let (ai, bi) = positions[k];
            match ops[k] {
                Op::Keep => out.push_str(&format!(" {}\n", a[ai])),
                Op::Del => out.push_str(&format!("-{}\n", a[ai])),
                Op::Add => out.push_str(&format!("+{}\n", b[bi])),
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Where the files are
// ---------------------------------------------------------------------------------------------

/// The environment that decides where a client keeps its configuration.
#[derive(Debug, Clone, Default)]
pub struct Roots {
    pub home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    /// Claude Code: `CLAUDE_CONFIG_DIR`.
    pub claude_config_dir: Option<PathBuf>,
    /// opencode: `OPENCODE_CONFIG` (an extra config file) and `OPENCODE_CONFIG_DIR`.
    pub opencode_config: Option<PathBuf>,
    pub opencode_config_dir: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
}

impl Roots {
    pub fn from_process() -> Self {
        let absolute = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        };
        Self {
            home: dirs::home_dir(),
            xdg_config_home: absolute("XDG_CONFIG_HOME"),
            claude_config_dir: absolute("CLAUDE_CONFIG_DIR"),
            opencode_config: absolute("OPENCODE_CONFIG"),
            opencode_config_dir: absolute("OPENCODE_CONFIG_DIR"),
            cwd: std::env::current_dir().ok(),
        }
    }

    /// opencode's user directory: `$XDG_CONFIG_HOME/opencode`, else `~/.config/opencode`.
    pub fn opencode_user_dir(&self) -> Option<PathBuf> {
        self.xdg_config_home
            .clone()
            .or_else(|| self.home.as_ref().map(|home| home.join(".config")))
            .map(|dir| dir.join("opencode"))
    }

    /// Claude Code's user directory: `$CLAUDE_CONFIG_DIR`, else `~/.claude`.
    pub fn claude_user_dir(&self) -> Option<PathBuf> {
        self.claude_config_dir
            .clone()
            .or_else(|| self.home.as_ref().map(|home| home.join(".claude")))
    }
}

/// Which configuration of a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    User,
    Project(PathBuf),
}

/// The file an install changes. For opencode, `opencode.jsonc` is used when it exists and
/// `opencode.json` does not.
pub fn config_path(client: McpInstallClient, scope: &Scope, roots: &Roots) -> Option<PathBuf> {
    match (client, scope) {
        (McpInstallClient::Opencode, scope) => {
            let dir = match scope {
                Scope::User => roots.opencode_user_dir()?,
                Scope::Project(dir) => dir.clone(),
            };
            let json = dir.join("opencode.json");
            let jsonc = dir.join("opencode.jsonc");
            Some(if !json.exists() && jsonc.exists() {
                jsonc
            } else {
                json
            })
        }
        // `$CLAUDE_CONFIG_DIR/.claude.json` when the variable is set, else `~/.claude.json`.
        (McpInstallClient::ClaudeCode, Scope::User) => match &roots.claude_config_dir {
            Some(dir) => Some(dir.join(".claude.json")),
            None => roots.home.as_ref().map(|home| home.join(".claude.json")),
        },
        (McpInstallClient::ClaudeCode, Scope::Project(dir)) => Some(dir.join(".mcp.json")),
    }
}

/// The directory of the client's skills (`<dir>/passless-agent/SKILL.md` goes under it), and the
/// directory the skill's path must stay inside.
pub fn skill_dirs(
    client: McpInstallClient,
    scope: &Scope,
    roots: &Roots,
) -> Option<(PathBuf, PathBuf)> {
    match (client, scope) {
        (McpInstallClient::Opencode, Scope::User) => {
            let root = roots.opencode_user_dir()?;
            Some((root.join("skills"), root))
        }
        (McpInstallClient::ClaudeCode, Scope::User) => {
            let root = roots.claude_user_dir()?;
            Some((root.join("skills"), root))
        }
        (McpInstallClient::Opencode, Scope::Project(dir)) => {
            Some((dir.join(".opencode/skills"), dir.clone()))
        }
        (McpInstallClient::ClaudeCode, Scope::Project(dir)) => {
            Some((dir.join(".claude/skills"), dir.clone()))
        }
    }
}

/// A configuration file `doctor --agents` looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub client: McpInstallClient,
    pub scope: Scope,
    pub path: PathBuf,
    /// This is the file `agent mcp install` would change for `client` and `scope`.
    pub installable: bool,
}

/// The existing configuration files of both clients: the user-scope files and `opencode.json(c)`
/// and `.mcp.json` of the working directory.
pub fn doctor_targets(roots: &Roots) -> Vec<Target> {
    let mut targets: Vec<Target> = Vec::new();
    let mut push = |client, scope: Scope, path: PathBuf, installable: bool| {
        if !path.is_file() {
            return;
        }
        let canonical = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        let same = |other: &Target| {
            std::fs::canonicalize(&other.path).unwrap_or_else(|_| other.path.clone()) == canonical
        };
        if !targets.iter().any(same) {
            targets.push(Target {
                client,
                scope,
                path,
                installable,
            });
        }
    };
    let user = Scope::User;
    if let Some(path) = config_path(McpInstallClient::Opencode, &user, roots) {
        push(McpInstallClient::Opencode, Scope::User, path, true);
    }
    if let Some(dir) = roots.opencode_user_dir() {
        push(
            McpInstallClient::Opencode,
            Scope::User,
            dir.join("opencode.jsonc"),
            false,
        );
    }
    if let Some(path) = &roots.opencode_config {
        push(McpInstallClient::Opencode, Scope::User, path.clone(), false);
    }
    if let Some(dir) = &roots.opencode_config_dir {
        for name in ["opencode.json", "opencode.jsonc"] {
            push(
                McpInstallClient::Opencode,
                Scope::User,
                dir.join(name),
                false,
            );
        }
    }
    if let Some(path) = config_path(McpInstallClient::ClaudeCode, &user, roots) {
        push(McpInstallClient::ClaudeCode, Scope::User, path, true);
    }
    if let Some(cwd) = &roots.cwd {
        let project = Scope::Project(cwd.clone());
        if let Some(path) = config_path(McpInstallClient::Opencode, &project, roots) {
            push(McpInstallClient::Opencode, project.clone(), path, true);
        }
        push(
            McpInstallClient::Opencode,
            project.clone(),
            cwd.join("opencode.jsonc"),
            false,
        );
        push(
            McpInstallClient::ClaudeCode,
            project.clone(),
            cwd.join(".mcp.json"),
            true,
        );
    }
    targets
}

// ---------------------------------------------------------------------------------------------
// Entries that shadow a user-level Passless entry
// ---------------------------------------------------------------------------------------------

/// Which configuration overrides the user-level entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowScope {
    /// Claude Code local scope: `projects[<abs path>].mcpServers` of the user-level file.
    Local,
    /// A project file: Claude Code `.mcp.json`, opencode `opencode.json(c)`.
    Project,
}

/// A plain (not Passless) server named `playwright` that overrides the user-level Passless one.
#[derive(Debug, Clone)]
pub struct Shadow {
    pub client: McpInstallClient,
    pub scope: ShadowScope,
    /// The user-level file with the Passless entry.
    pub user_file: PathBuf,
    /// The user-level Passless entry, as the client's JSON.
    pub user_entry: Value,
    /// The file with the entry that wins.
    pub file: PathBuf,
    /// What the winning entry is (`it runs ...`).
    pub what: String,
    /// The precedence is documented for this case. Otherwise (an ancestor directory's file,
    /// opencode's merge of several files) the entry only may win.
    pub certain: bool,
}

/// How a server named `playwright` appears in a parsed file at `path`.
enum Named {
    Passless(Value),
    Other(String),
}

fn named_server(client: McpInstallClient, root: &Value, path: &[&str]) -> Option<Named> {
    let owned: Vec<String> = path.iter().map(|key| (*key).to_owned()).collect();
    let value = root_value(root, &owned)?;
    let found = find_entries(client, root)
        .into_iter()
        .find(|found| found.entry.path == owned);
    Some(match found {
        Some(found) if matches!(found.kind, Kind::Wrapped { .. }) => Named::Passless(value.clone()),
        _ => Named::Other(describe_existing(value)),
    })
}

fn read_config(path: &Path) -> Option<Value> {
    parse_config(&std::fs::read_to_string(path).ok()?)
        .ok()
        .map(|(root, _)| root)
}

/// The plain `playwright` entries that win over a user-level Passless `playwright` entry in the
/// current directory. Claude Code: local scope, then a project `.mcp.json` (the working directory
/// and its ancestors), then user scope. opencode: a project `opencode.json(c)` is merged over the
/// global one.
pub fn find_shadows(roots: &Roots) -> Vec<Shadow> {
    let mut shadows = Vec::new();
    let Some(cwd) = roots.cwd.as_deref() else {
        return shadows;
    };
    let name = NEW_ENTRY_NAME;

    if let Some(user_file) = config_path(McpInstallClient::ClaudeCode, &Scope::User, roots)
        && let Some(user_root) = read_config(&user_file)
        && let Some(Named::Passless(user_entry)) = named_server(
            McpInstallClient::ClaudeCode,
            &user_root,
            &["mcpServers", name],
        )
    {
        let canonical = std::fs::canonicalize(cwd).ok();
        let keys: Vec<String> = [Some(cwd.to_path_buf()), canonical]
            .into_iter()
            .flatten()
            .map(|dir| dir.to_string_lossy().into_owned())
            .collect();
        let project_key = keys.iter().find(|key| {
            user_root
                .get("projects")
                .and_then(|projects| projects.get(key.as_str()))
                .is_some()
        });
        let local = project_key.and_then(|key| {
            named_server(
                McpInstallClient::ClaudeCode,
                &user_root,
                &["projects", key, "mcpServers", name],
            )
        });
        match local {
            Some(Named::Other(what)) => shadows.push(Shadow {
                client: McpInstallClient::ClaudeCode,
                scope: ShadowScope::Local,
                user_file: user_file.clone(),
                user_entry: user_entry.clone(),
                file: user_file.clone(),
                what,
                certain: true,
            }),
            // A Passless entry in local scope wins: nothing is shadowed.
            Some(Named::Passless(_)) => {}
            None => {
                let disabled = project_key
                    .and_then(|key| {
                        user_root["projects"][key.as_str()].get("disabledMcpjsonServers")
                    })
                    .and_then(Value::as_array)
                    .is_some_and(|names| names.iter().any(|n| n.as_str() == Some(name)));
                for (depth, dir) in cwd.ancestors().enumerate() {
                    let file = dir.join(".mcp.json");
                    let Some(root) = read_config(&file) else {
                        continue;
                    };
                    match named_server(McpInstallClient::ClaudeCode, &root, &["mcpServers", name]) {
                        Some(Named::Other(what)) if !disabled => shadows.push(Shadow {
                            client: McpInstallClient::ClaudeCode,
                            scope: ShadowScope::Project,
                            user_file: user_file.clone(),
                            user_entry: user_entry.clone(),
                            file,
                            what,
                            certain: depth == 0,
                        }),
                        Some(_) => {}
                        None => continue,
                    }
                    break;
                }
            }
        }
    }

    // opencode: the user-level files, then the project file of the working directory.
    let targets = doctor_targets(roots);
    let opencode = |scope_is_user: bool| {
        targets.iter().filter(move |target| {
            target.client == McpInstallClient::Opencode
                && matches!(target.scope, Scope::User) == scope_is_user
        })
    };
    let user = opencode(true).find_map(|target| {
        let root = read_config(&target.path)?;
        [vec!["mcp", "servers", name], vec!["mcp", name]]
            .iter()
            .find_map(
                |path| match named_server(McpInstallClient::Opencode, &root, path)? {
                    Named::Passless(entry) => Some((target.path.clone(), entry)),
                    Named::Other(_) => None,
                },
            )
    });
    if let Some((user_file, user_entry)) = user {
        for target in opencode(false) {
            let Some(root) = read_config(&target.path) else {
                continue;
            };
            let plain = [vec!["mcp", "servers", name], vec!["mcp", name]]
                .iter()
                .find_map(
                    |path| match named_server(McpInstallClient::Opencode, &root, path)? {
                        Named::Other(what) => Some(what),
                        Named::Passless(_) => None,
                    },
                );
            if let Some(what) = plain {
                shadows.push(Shadow {
                    client: McpInstallClient::Opencode,
                    scope: ShadowScope::Project,
                    user_file: user_file.clone(),
                    user_entry: user_entry.clone(),
                    file: target.path.clone(),
                    what,
                    certain: false,
                });
            }
        }
    }
    shadows
}

pub fn client_name(client: McpInstallClient) -> &'static str {
    match client {
        McpInstallClient::Opencode => "opencode",
        McpInstallClient::ClaudeCode => "claude-code",
    }
}

/// The `passless agent mcp install` command line that fixes `target`.
pub fn install_command(target: &Target, profile: &str) -> String {
    let scope = match &target.scope {
        Scope::User => "--user".to_owned(),
        Scope::Project(dir) => format!("--project {}", shell_word(&dir.to_string_lossy())),
    };
    format!(
        "passless agent mcp install --client {} {scope} --profile {profile} --yes",
        client_name(target.client)
    )
}

pub fn shell_word(word: &str) -> String {
    if !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+=:@%,".contains(c))
    {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// `YYYYMMDDTHHMMSSZ` for a time since the epoch.
pub fn utc_timestamp(since_epoch: std::time::Duration) -> String {
    let secs = since_epoch.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests;
