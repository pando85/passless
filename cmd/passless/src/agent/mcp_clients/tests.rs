use super::*;

const PASSLESS: &str = "/usr/bin/passless";

fn s(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

/// opencode's user config: `mcp.servers`, `npx -y @playwright/mcp@latest` with an absolute npx.
const OPENCODE: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "searxng": {
        "type": "local",
        "command": [
          "npx",
          "-y",
          "mcp-searxng"
        ],
        "environment": {
          "SEARXNG_URL": "<redacted>"
        }
      },
      "playwright": {
        "type": "local",
        "command": [
          "/usr/bin/npx",
          "-y",
          "@playwright/mcp@latest"
        ],
        "enabled": true,
        "timeout": 30000
      },
      "firefox-devtools": {
        "type": "local",
        "command": [
          "/usr/bin/npx",
          "-y",
          "@mozilla/firefox-devtools-mcp@latest",
          "--connect-existing"
        ]
      }
    }
  }
}
"#;

/// A project `.mcp.json`: `pnpm dlx` with a pin and the usual flags.
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

/// A `.mcp.json` with compact arrays, other servers and an `env`.
const GITOPS: &str = r#"{
  "mcpServers": {
    "trustyou": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/example/mcp:latest"],
      "env": {
        "BASE_URL": "<redacted>"
      }
    },
    "google-drive": {
      "command": "bash",
      "args": ["${GITOPS_PATH}/scripts/gdrive-mcp.sh"]
    },
    "playwright": {
      "command": "npx",
      "args": ["@playwright/mcp@latest"]
    },
    "slack": {
      "command": "bash",
      "args": ["${GITOPS_PATH}/scripts/slack-mcp.sh"]
    }
  }
}
"#;

// ---- detection --------------------------------------------------------------------------------

fn plain(argv: &[&str]) -> PlainLaunch {
    match classify(&s(argv)) {
        Kind::Plain(launch) => launch,
        other => panic!("{argv:?} classified as {other:?}"),
    }
}

#[test]
fn every_runner_of_playwright_mcp_is_detected() {
    for (argv, runner, package) in [
        (
            &["npx", "-y", "@playwright/mcp@latest"][..],
            Runner::Npx,
            Some("@playwright/mcp@latest"),
        ),
        (&["npx", "@playwright/mcp"], Runner::Npx, None),
        (
            &["/usr/bin/npx", "--yes", "@playwright/mcp@0.0.83"],
            Runner::Npx,
            Some("@playwright/mcp@0.0.83"),
        ),
        (
            &["pnpm", "dlx", "@playwright/mcp@0.0.83"],
            Runner::PnpmDlx,
            Some("@playwright/mcp@0.0.83"),
        ),
        (
            &["pnpx", "@playwright/mcp@0.0.83"],
            Runner::PnpmDlx,
            Some("@playwright/mcp@0.0.83"),
        ),
        (
            &["bunx", "@playwright/mcp@latest"],
            Runner::Bunx,
            Some("@playwright/mcp@latest"),
        ),
        (
            &["bun", "x", "@playwright/mcp@latest"],
            Runner::Bunx,
            Some("@playwright/mcp@latest"),
        ),
        (
            &["yarn", "dlx", "@playwright/mcp@0.0.85"],
            Runner::YarnDlx,
            Some("@playwright/mcp@0.0.85"),
        ),
        (
            &["npx", "-p", "@playwright/mcp@0.0.83", "playwright-mcp"],
            Runner::Npx,
            Some("@playwright/mcp@0.0.83"),
        ),
        (&["playwright-mcp"], Runner::Binary, None),
        (
            &["/opt/bin/mcp-server-playwright", "--isolated"],
            Runner::Binary,
            None,
        ),
    ] {
        let launch = plain(argv);
        assert_eq!(launch.adapter, McpAdapterKind::Playwright, "{argv:?}");
        assert_eq!(launch.runner, runner, "{argv:?}");
        assert_eq!(launch.package.as_deref(), package, "{argv:?}");
    }
}

#[test]
fn chrome_devtools_mcp_is_detected_the_same_ways() {
    for argv in [
        &["npx", "-y", "chrome-devtools-mcp@latest"][..],
        &["pnpm", "dlx", "chrome-devtools-mcp"],
        &["bunx", "chrome-devtools-mcp@1.12.0"],
        &["chrome-devtools-mcp"],
    ] {
        assert_eq!(
            plain(argv).adapter,
            McpAdapterKind::ChromeDevtools,
            "{argv:?}"
        );
    }
}

#[test]
fn the_arguments_after_the_package_are_the_servers() {
    let launch = plain(&[
        "pnpm",
        "dlx",
        "@playwright/mcp@0.0.83",
        "--isolated",
        "--caps",
        "pdf",
    ]);
    assert_eq!(launch.args, s(&["--isolated", "--caps", "pdf"]));
    let launch = plain(&[
        "npx",
        "-p",
        "@playwright/mcp@1",
        "playwright-mcp",
        "--isolated",
    ]);
    assert_eq!(launch.args, s(&["--isolated"]));
}

#[test]
fn an_absolute_npx_is_kept_and_other_runner_options_are_reported() {
    let launch = plain(&[
        "/usr/bin/npx",
        "-y",
        "--registry",
        "https://r.example",
        "@playwright/mcp",
    ]);
    assert_eq!(launch.npx_path.as_deref(), Some("/usr/bin/npx"));
    assert_eq!(launch.runner_notes.len(), 1, "{launch:?}");
    assert!(launch.runner_notes[0].contains("--registry"));
    assert_eq!(plain(&["npx", "@playwright/mcp"]).npx_path, None);
    assert_eq!(
        plain(&["/usr/bin/pnpm", "dlx", "@playwright/mcp"]).npx_path,
        None
    );
}

#[test]
fn other_servers_are_not_browser_servers() {
    for argv in [
        &["npx", "-y", "mcp-searxng"][..],
        &[
            "npx",
            "-y",
            "@mozilla/firefox-devtools-mcp@latest",
            "--connect-existing",
        ],
        &["pnpm", "dlx", "something-else"],
        &["pnpm", "run", "dev"],
        &["bash", "/scripts/grafana-mcp.sh"],
        &["docker", "run", "--rm", "-i", "ghcr.io/example/mcp:latest"],
        &["npx"],
        &[],
    ] {
        assert_eq!(classify(&s(argv)), Kind::Other, "{argv:?}");
    }
}

#[test]
fn launches_the_installer_cannot_rewrite_are_reported_as_unsupported() {
    for argv in [
        &["node", "/home/u/proj/node_modules/@playwright/mcp/cli.js"][..],
        &["sh", "-c", "npx @playwright/mcp@latest --headless"],
        &["npx", "-c", "playwright-mcp --headless"],
        &["docker", "run", "-i", "mcr.microsoft.com/playwright/mcp"],
    ] {
        assert!(
            matches!(classify(&s(argv)), Kind::Unsupported { .. }),
            "{argv:?}"
        );
    }
}

#[test]
fn wrapped_entries_are_recognised_with_their_profile() {
    assert_eq!(
        classify(&s(&[
            "/usr/bin/passless",
            "agent",
            "mcp",
            "playwright",
            "--profile",
            "agent"
        ])),
        Kind::Wrapped {
            adapter: McpAdapterKind::Playwright,
            profile: Some("agent".into())
        }
    );
    assert_eq!(
        classify(&s(&[
            "passless",
            "agent",
            "mcp",
            "chrome-devtools",
            "--profile=work",
            "--",
            "--slim"
        ])),
        Kind::Wrapped {
            adapter: McpAdapterKind::ChromeDevtools,
            profile: Some("work".into())
        }
    );
    // The deprecated alias is Passless too.
    assert!(matches!(
        classify(&s(&[
            "passless",
            "agent",
            "playwright-mcp",
            "--profile",
            "p",
            "--",
            "/usr/bin/npx"
        ])),
        Kind::Wrapped { .. }
    ));
    assert_eq!(
        classify(&s(&["passless", "agent", "mcp", "playwright"])),
        Kind::Wrapped {
            adapter: McpAdapterKind::Playwright,
            profile: None
        }
    );
}

// ---- rewrite ----------------------------------------------------------------------------------

fn rewritten(argv: &[&str]) -> Rewrite {
    rewrite(&plain(argv), PASSLESS, "agent", &[], false)
}

#[test]
fn the_package_pin_becomes_package() {
    let out = rewritten(&["pnpm", "dlx", "@playwright/mcp@0.0.83"]);
    assert_eq!(
        out.argv,
        s(&[
            "/usr/bin/passless",
            "agent",
            "mcp",
            "playwright",
            "--profile",
            "agent",
            "--package",
            "@playwright/mcp@0.0.83"
        ])
    );
    // Without a version the wrapper's default package is the same.
    let out = rewritten(&["npx", "@playwright/mcp"]);
    assert_eq!(
        out.argv,
        s(&[
            "/usr/bin/passless",
            "agent",
            "mcp",
            "playwright",
            "--profile",
            "agent"
        ])
    );
    // `@latest` is kept as written: it differs from the bare name for npx.
    assert!(
        rewritten(&["npx", "-y", "@playwright/mcp@latest"])
            .argv
            .contains(&"@playwright/mcp@latest".to_owned())
    );
}

#[test]
fn the_runner_maps_to_npx_with_a_note_unless_it_already_was_npx() {
    assert!(
        rewritten(&["npx", "-y", "@playwright/mcp"])
            .notes
            .is_empty()
    );
    for (argv, label) in [
        (&["pnpm", "dlx", "@playwright/mcp"][..], "pnpm dlx"),
        (&["bunx", "@playwright/mcp"], "bunx"),
        (&["yarn", "dlx", "@playwright/mcp"], "yarn dlx"),
    ] {
        let out = rewritten(argv);
        assert!(
            out.notes
                .iter()
                .any(|n| n.contains(label) && n.contains("npx")),
            "{label}: {:?}",
            out.notes
        );
        assert!(!out.argv.contains(&"--npx".to_owned()));
    }
    let out = rewritten(&["playwright-mcp"]);
    assert!(
        out.notes.iter().any(|n| n.contains("local executable")),
        "{:?}",
        out.notes
    );
    // An absolute npx stays the wrapper's npx.
    let out = rewritten(&["/usr/bin/npx", "-y", "@playwright/mcp@latest"]);
    assert_eq!(&out.argv[6..8], ["--npx", "/usr/bin/npx"]);
}

#[test]
fn compatible_flags_pass_through_after_the_separator() {
    let out = rewritten(&[
        "npx",
        "-y",
        "@playwright/mcp@0.0.83",
        "--viewport-size",
        "1440,900",
        "--isolated",
        "--caps",
        "vision,pdf",
        "--output-dir",
        "/tmp/out",
        "--save-trace",
        "--timeout-action=7000",
        "--user-agent",
        "Agent/1",
    ]);
    let at = out
        .argv
        .iter()
        .position(|a| a == "--")
        .expect("a separator");
    assert_eq!(
        out.argv[at + 1..],
        s(&[
            "--viewport-size",
            "1440,900",
            "--isolated",
            "--caps",
            "vision,pdf",
            "--output-dir",
            "/tmp/out",
            "--save-trace",
            "--timeout-action=7000",
            "--user-agent",
            "Agent/1"
        ])
    );
    assert!(out.notes.is_empty(), "{:?}", out.notes);
    // No flags, no separator.
    assert!(
        !rewritten(&["npx", "@playwright/mcp"])
            .argv
            .contains(&"--".to_owned())
    );
}

#[test]
fn flags_that_conflict_with_a_managed_browser_are_dropped_with_a_note_each() {
    let out = rewritten(&[
        "npx",
        "@playwright/mcp",
        "--browser",
        "firefox",
        "--executable-path",
        "/opt/chrome",
        "--user-data-dir=/tmp/p",
        "--cdp-endpoint",
        "http://127.0.0.1:9222",
        "--cdp-header",
        "Authorization: Bearer hunter2",
        "X-Other: 1",
        "--extension",
        "--endpoint",
        "ws://x",
        "--device",
        "iPhone 15",
        "--mobile",
        "--no-sandbox",
        "--sandbox",
        "--headless",
        "--headed",
        "--port",
        "8931",
        "--isolated",
    ]);
    // Only --isolated survives.
    assert_eq!(&out.argv[6..], ["--", "--isolated"]);
    for flag in [
        "--browser",
        "--executable-path",
        "--user-data-dir",
        "--cdp-endpoint",
        "--cdp-header",
        "--extension",
        "--endpoint",
        "--device",
        "--mobile",
        "--no-sandbox",
        "--sandbox",
        "--headless",
        "--headed",
        "--port",
    ] {
        assert_eq!(
            out.notes
                .iter()
                .filter(|n| n.starts_with(&format!("dropped `{flag}`")))
                .count(),
            1,
            "{flag}: {:?}",
            out.notes
        );
    }
    // The values never reach the notes (a header can be a credential).
    let text = out.notes.join("\n");
    assert!(
        !text.contains("hunter2") && !text.contains("/opt/chrome"),
        "{text}"
    );
    let headless = out
        .notes
        .iter()
        .find(|n| n.contains("`--headless`"))
        .unwrap();
    assert!(
        headless.contains("headed or headless comes from the Passless profile"),
        "{headless}"
    );
}

#[test]
fn a_value_flag_does_not_swallow_a_following_flag_that_is_kept() {
    // `--browser` takes one value; `--isolated` after it is the user's flag.
    let out = rewritten(&[
        "npx",
        "@playwright/mcp",
        "--browser",
        "chromium",
        "--isolated",
    ]);
    assert_eq!(&out.argv[6..], ["--", "--isolated"]);
    // `--cdp-header` takes several values, up to the next flag.
    let out = rewritten(&[
        "npx",
        "@playwright/mcp",
        "--cdp-header",
        "A: 1",
        "B: 2",
        "--isolated",
    ]);
    assert_eq!(&out.argv[6..], ["--", "--isolated"]);
}

#[test]
fn chrome_devtools_flags_are_matched_in_camel_and_kebab_case() {
    let out = rewrite(
        &plain(&[
            "npx",
            "-y",
            "chrome-devtools-mcp@latest",
            "--browser-url",
            "http://127.0.0.1:9222",
            "-w",
            "ws://x",
            "--executablePath",
            "/opt/chrome",
            "--headless",
            "--isolated",
            "--chrome-arg=--foo",
            "--viewport=1280x720",
            "--slim",
            "--category-network=false",
        ]),
        PASSLESS,
        "agent",
        &[],
        false,
    );
    assert_eq!(
        out.argv,
        s(&[
            "/usr/bin/passless",
            "agent",
            "mcp",
            "chrome-devtools",
            "--profile",
            "agent",
            "--package",
            "chrome-devtools-mcp@latest",
            "--",
            "--slim",
            "--category-network=false"
        ])
    );
    assert_eq!(out.notes.len(), 7, "{:?}", out.notes);
}

#[test]
fn conflicting_environment_and_config_files_are_reported() {
    let launch = plain(&["npx", "@playwright/mcp", "--config", "pw.json"]);
    let out = rewrite(
        &launch,
        PASSLESS,
        "agent",
        &s(&["PLAYWRIGHT_MCP_BROWSER", "HTTPS_PROXY"]),
        false,
    );
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("PLAYWRIGHT_MCP_BROWSER")),
        "{:?}",
        out.notes
    );
    assert!(out.notes.iter().all(|n| !n.contains("HTTPS_PROXY")));
    assert!(out.notes.iter().any(|n| n.contains("--config")));
    assert!(out.argv.contains(&"--config".to_owned()), "{:?}", out.argv);
}

// ---- rewriting files --------------------------------------------------------------------------

fn plan_of(client: McpInstallClient, text: &str) -> Plan {
    plan(client, text, PASSLESS, "agent", false).expect("a plan")
}

#[test]
fn a_pnpm_dlx_project_entry_is_rewritten_in_place_and_nothing_else_changes() {
    let plan = plan_of(McpInstallClient::ClaudeCode, CALYPSO);
    let new = plan.new_text.expect("a rewrite");
    let expected = CALYPSO.replace(
        r#"      "command": "pnpm",
      "args": [
        "dlx",
        "@playwright/mcp@0.0.83",
        "--browser",
        "chromium",
        "--headless",
        "--isolated",
        "--viewport-size",
        "1440,900"
      ]"#,
        r#"      "command": "/usr/bin/passless",
      "args": [
        "agent",
        "mcp",
        "playwright",
        "--profile",
        "agent",
        "--package",
        "@playwright/mcp@0.0.83",
        "--",
        "--isolated",
        "--viewport-size",
        "1440,900"
      ]"#,
    );
    assert_eq!(new, expected);
    let Outcome::Rewritten { notes, runner, .. } = &plan.entries[0].outcome else {
        panic!()
    };
    assert_eq!(runner, "pnpm dlx");
    // --browser and --headless were dropped; the runner changed.
    assert_eq!(notes.len(), 3, "{notes:?}");
}

#[test]
fn compact_arrays_stay_compact_and_other_entries_are_untouched() {
    let plan = plan_of(McpInstallClient::ClaudeCode, GITOPS);
    let expected = GITOPS.replace(
        r#"      "command": "npx",
      "args": ["@playwright/mcp@latest"]"#,
        r#"      "command": "/usr/bin/passless",
      "args": ["agent", "mcp", "playwright", "--profile", "agent", "--package", "@playwright/mcp@latest"]"#,
    );
    assert_eq!(plan.new_text.as_deref(), Some(expected.as_str()));
    assert_eq!(
        plan.entries.len(),
        1,
        "only the playwright entry is a browser server"
    );
}

#[test]
fn an_opencode_entry_keeps_its_other_keys_and_its_runner_path() {
    let plan = plan_of(McpInstallClient::Opencode, OPENCODE);
    let expected = OPENCODE.replace(
        r#"        "command": [
          "/usr/bin/npx",
          "-y",
          "@playwright/mcp@latest"
        ],
        "enabled": true,
        "timeout": 30000"#,
        r#"        "command": [
          "/usr/bin/passless",
          "agent",
          "mcp",
          "playwright",
          "--profile",
          "agent",
          "--npx",
          "/usr/bin/npx",
          "--package",
          "@playwright/mcp@latest"
        ],
        "enabled": true,
        "timeout": 30000"#,
    );
    assert_eq!(plan.new_text.as_deref(), Some(expected.as_str()));
    assert_eq!(plan.entries.len(), 1);
    assert_eq!(plan.entries[0].entry.location(), "mcp.servers.playwright");
}

#[test]
fn the_legacy_opencode_layout_is_handled_too() {
    let text = r#"{"mcp": {"playwright": {"type": "local", "command": ["npx", "-y", "@playwright/mcp@latest", "--isolated"]}, "timeout": {"startup": 5}}}"#;
    let plan = plan_of(McpInstallClient::Opencode, text);
    assert_eq!(plan.entries[0].entry.location(), "mcp.playwright");
    assert_eq!(
        plan.new_text.as_deref(),
        Some(
            r#"{"mcp": {"playwright": {"type": "local", "command": ["/usr/bin/passless", "agent", "mcp", "playwright", "--profile", "agent", "--package", "@playwright/mcp@latest", "--", "--isolated"]}, "timeout": {"startup": 5}}}"#
        )
    );
}

#[test]
fn a_claude_entry_without_args_gets_them_inserted_in_the_files_layout() {
    let text = "{\n  \"mcpServers\": {\n    \"pw\": {\n      \"type\": \"stdio\",\n      \"command\": \"playwright-mcp\",\n      \"env\": {\"A\": \"1\"}\n    }\n  }\n}\n";
    let plan = plan_of(McpInstallClient::ClaudeCode, text);
    let new = plan.new_text.unwrap();
    assert!(
        new.contains(
            "      \"command\": \"/usr/bin/passless\",\n      \"args\": [\n        \"agent\","
        ),
        "{new}"
    );
    assert!(new.contains("\"env\": {\"A\": \"1\"}"), "{new}");
    // And on one line.
    let one = r#"{"mcpServers":{"pw":{"command":"playwright-mcp"}}}"#;
    let new = plan_of(McpInstallClient::ClaudeCode, one).new_text.unwrap();
    assert!(
        new.starts_with(r#"{"mcpServers":{"pw":{"command":"/usr/bin/passless", "args": ["agent""#),
        "{new}"
    );
    assert!(serde_json::from_str::<Value>(&new).is_ok());
}

#[test]
fn several_entries_in_one_file_are_all_rewritten() {
    let text = r#"{
  "mcpServers": {
    "a": { "command": "npx", "args": ["-y", "@playwright/mcp@0.0.83", "--isolated"] },
    "b": { "command": "bunx", "args": ["chrome-devtools-mcp@latest", "--headless"] },
    "c": { "command": "bash", "args": ["x.sh"] }
  }
}
"#;
    let plan = plan_of(McpInstallClient::ClaudeCode, text);
    assert_eq!(plan.rewritten().count(), 2);
    let (root, _) = parse_config(plan.new_text.as_deref().unwrap()).unwrap();
    assert_eq!(root["mcpServers"]["c"]["args"], serde_json::json!(["x.sh"]));
    assert_eq!(root["mcpServers"]["b"]["args"][2], "chrome-devtools");
    assert_eq!(root["mcpServers"]["a"]["command"], PASSLESS);
}

#[test]
fn the_rest_of_a_large_file_is_preserved_byte_for_byte() {
    // Like ~/.claude.json: floats, large numbers, unicode and escapes elsewhere in the file.
    let text = "{\n  \"numStartups\": 12,\n  \"ratio\": 0.1000000000000000055,\n  \"big\": 1e21,\n  \"name\": \"caf\\u00e9 \\\"q\\\"\",\n  \"mcpServers\": {\n    \"playwright\": {\"command\": \"npx\", \"args\": [\"-y\", \"@playwright/mcp\"]}\n  },\n  \"projects\": {}\n}\n";
    let new = plan_of(McpInstallClient::ClaudeCode, text)
        .new_text
        .unwrap();
    assert!(new.starts_with(&text[..text.find("\"playwright\"").unwrap()]));
    assert!(new.ends_with("  },\n  \"projects\": {}\n}\n"));
    assert!(
        new.contains("0.1000000000000000055") && new.contains("1e21") && new.contains("caf\\u00e9")
    );
}

#[test]
fn a_rewritten_file_is_already_wrapped_and_a_second_pass_changes_nothing() {
    for (client, text) in [
        (McpInstallClient::Opencode, OPENCODE),
        (McpInstallClient::ClaudeCode, CALYPSO),
        (McpInstallClient::ClaudeCode, GITOPS),
    ] {
        let first = plan_of(client, text).new_text.unwrap();
        let second = plan_of(client, &first);
        assert!(second.new_text.is_none());
        assert_eq!(second.rewritten().count(), 0);
        assert!(
            second.entries.iter().any(|e| matches!(
                &e.outcome,
                Outcome::AlreadyWrapped { profile: Some(p), .. } if p == "agent"
            )),
            "{:?}",
            second.entries
        );
        // Another profile does not rewrite a wrapped entry either.
        let other = plan(client, &first, PASSLESS, "other", false).unwrap();
        assert!(other.new_text.is_none());
    }
}

#[test]
fn a_file_with_comments_is_analysed_but_never_rewritten() {
    let text = "{\n  // browser for the agent\n  \"mcpServers\": {\n    \"playwright\": {\"command\": \"npx\", \"args\": [\"@playwright/mcp@latest\"]}, /* old */\n  },\n}\n";
    assert!(serde_json::from_str::<Value>(text).is_err());
    let plan = plan_of(McpInstallClient::ClaudeCode, text);
    assert!(plan.jsonc);
    assert!(plan.new_text.is_none());
    let Outcome::Rewritten { snippet, .. } = &plan.entries[0].outcome else {
        panic!()
    };
    let snippet: Value = serde_json::from_str(snippet).expect("the snippet is JSON");
    assert_eq!(snippet["playwright"]["command"], PASSLESS);
    assert_eq!(snippet["playwright"]["type"], "stdio");
    // Trailing commas alone make it JSONC as well.
    let trailing = r#"{"mcpServers": {"p": {"command": "npx", "args": ["@playwright/mcp"],},},}"#;
    assert!(plan_of(McpInstallClient::ClaudeCode, trailing).jsonc);
    // `//` inside a string is not a comment.
    let url = r#"{"mcpServers": {"p": {"command": "npx", "args": ["@playwright/mcp", "--allowed-origins", "https://x.test"]}}}"#;
    assert!(!plan_of(McpInstallClient::ClaudeCode, url).jsonc);
}

#[test]
fn text_that_is_not_json_is_an_error() {
    assert!(matches!(
        plan(
            McpInstallClient::ClaudeCode,
            "{ not json",
            PASSLESS,
            "agent",
            false
        ),
        Err(PlanError::Invalid(_))
    ));
    assert!(matches!(
        plan(McpInstallClient::Opencode, "", PASSLESS, "agent", false),
        Err(PlanError::Invalid(_))
    ));
}

#[test]
fn unsupported_entries_get_a_snippet_and_are_left_alone() {
    let text = r#"{"mcpServers": {"pw": {"command": "node", "args": ["/p/node_modules/@playwright/mcp/cli.js"]}}}"#;
    let plan = plan_of(McpInstallClient::ClaudeCode, text);
    assert!(plan.new_text.is_none());
    let Outcome::Unsupported {
        snippet, adapter, ..
    } = &plan.entries[0].outcome
    else {
        panic!()
    };
    assert_eq!(*adapter, McpAdapterKind::Playwright);
    assert!(
        snippet.contains("\"mcp\"") && snippet.contains("--profile"),
        "{snippet}"
    );
}

#[test]
fn http_and_other_typed_entries_are_ignored() {
    let text = r#"{"mcpServers": {"remote": {"type": "http", "url": "https://x.test/mcp", "command": "npx", "args": ["@playwright/mcp"]}}}"#;
    assert!(
        plan_of(McpInstallClient::ClaudeCode, text)
            .entries
            .is_empty()
    );
    let text = r#"{"mcp": {"servers": {"r": {"type": "remote", "url": "https://x.test"}}}}"#;
    assert!(plan_of(McpInstallClient::Opencode, text).entries.is_empty());
}

// ---- diff -------------------------------------------------------------------------------------

#[test]
fn the_diff_shows_only_the_changed_lines_with_context() {
    let new = plan_of(McpInstallClient::ClaudeCode, CALYPSO)
        .new_text
        .unwrap();
    let diff = unified_diff("p/.mcp.json", CALYPSO, &new);
    assert!(
        diff.starts_with("--- a/p/.mcp.json\n+++ b/p/.mcp.json\n@@ -"),
        "{diff}"
    );
    assert!(
        diff.contains(
            "-      \"command\": \"pnpm\",\n+      \"command\": \"/usr/bin/passless\",\n"
        ),
        "{diff}"
    );
    assert!(diff.contains("-        \"dlx\",\n"), "{diff}");
    assert!(
        diff.contains(" {\n   \"mcpServers\": {\n"),
        "context: {diff}"
    );
    assert_eq!(unified_diff("x", CALYPSO, CALYPSO), "");
}

#[test]
fn diff_hunk_headers_count_lines() {
    let old = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\n";
    let new = "a\nB\nc\nd\ne\nf\ng\nh\ni\nj\nk\nL\n";
    let diff = unified_diff("f", old, new);
    // Two changes 10 lines apart: two hunks.
    assert_eq!(diff.matches("@@ -").count(), 2, "{diff}");
    assert!(diff.contains("@@ -1,5 +1,5 @@"), "{diff}");
    assert!(diff.contains("@@ -9,4 +9,4 @@"), "{diff}");
    let close = "a\nb\nc\nd\ne\n";
    let diff = unified_diff("f", close, "a\nB\nc\nD\ne\n");
    assert_eq!(diff.matches("@@ -").count(), 1, "{diff}");
    // Pure insertion and deletion.
    assert!(unified_diff("f", "a\nb\n", "a\nx\nb\n").contains("+x\n"));
    assert!(unified_diff("f", "a\nx\nb\n", "a\nb\n").contains("-x\n"));
}

// ---- paths ------------------------------------------------------------------------------------

fn roots(home: &Path) -> Roots {
    Roots {
        home: Some(home.to_owned()),
        ..Roots::default()
    }
}

#[test]
fn claude_code_user_scope_follows_claude_config_dir() {
    let home = PathBuf::from("/home/u");
    let plain = roots(&home);
    assert_eq!(
        config_path(McpInstallClient::ClaudeCode, &Scope::User, &plain),
        Some(PathBuf::from("/home/u/.claude.json"))
    );
    let personal = Roots {
        claude_config_dir: Some("/home/u/.claude-personal".into()),
        ..plain
    };
    assert_eq!(
        config_path(McpInstallClient::ClaudeCode, &Scope::User, &personal),
        Some(PathBuf::from("/home/u/.claude-personal/.claude.json"))
    );
    assert_eq!(
        skill_dirs(McpInstallClient::ClaudeCode, &Scope::User, &personal),
        Some((
            "/home/u/.claude-personal/skills".into(),
            "/home/u/.claude-personal".into()
        ))
    );
    assert_eq!(
        skill_dirs(McpInstallClient::ClaudeCode, &Scope::User, &roots(&home)),
        Some(("/home/u/.claude/skills".into(), "/home/u/.claude".into()))
    );
}

#[test]
fn opencode_user_scope_follows_xdg_config_home() {
    let home = PathBuf::from("/home/u");
    assert_eq!(
        config_path(McpInstallClient::Opencode, &Scope::User, &roots(&home)),
        Some(PathBuf::from("/home/u/.config/opencode/opencode.json"))
    );
    let xdg = Roots {
        xdg_config_home: Some("/x/cfg".into()),
        ..roots(&home)
    };
    assert_eq!(
        config_path(McpInstallClient::Opencode, &Scope::User, &xdg),
        Some(PathBuf::from("/x/cfg/opencode/opencode.json"))
    );
    assert_eq!(
        skill_dirs(McpInstallClient::Opencode, &Scope::User, &xdg),
        Some(("/x/cfg/opencode/skills".into(), "/x/cfg/opencode".into()))
    );
}

#[test]
fn project_scope_files() {
    let dir = tempfile::tempdir().unwrap();
    let scope = Scope::Project(dir.path().to_owned());
    let none = Roots::default();
    assert_eq!(
        config_path(McpInstallClient::ClaudeCode, &scope, &none),
        Some(dir.path().join(".mcp.json"))
    );
    assert_eq!(
        config_path(McpInstallClient::Opencode, &scope, &none),
        Some(dir.path().join("opencode.json"))
    );
    // opencode.jsonc is used when it is the only one.
    std::fs::write(dir.path().join("opencode.jsonc"), "{}").unwrap();
    assert_eq!(
        config_path(McpInstallClient::Opencode, &scope, &none),
        Some(dir.path().join("opencode.jsonc"))
    );
    std::fs::write(dir.path().join("opencode.json"), "{}").unwrap();
    assert_eq!(
        config_path(McpInstallClient::Opencode, &scope, &none),
        Some(dir.path().join("opencode.json"))
    );
    assert_eq!(
        skill_dirs(McpInstallClient::Opencode, &scope, &none),
        Some((dir.path().join(".opencode/skills"), dir.path().to_owned()))
    );
    assert_eq!(
        skill_dirs(McpInstallClient::ClaudeCode, &scope, &none),
        Some((dir.path().join(".claude/skills"), dir.path().to_owned()))
    );
}

#[test]
fn the_doctor_looks_at_user_scope_and_the_working_directory_once_each() {
    let home = tempfile::tempdir().unwrap();
    let claude = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".config/opencode")).unwrap();
    std::fs::write(home.path().join(".config/opencode/opencode.json"), "{}").unwrap();
    std::fs::write(home.path().join(".claude.json"), "{}").unwrap(); // ignored: CLAUDE_CONFIG_DIR wins
    std::fs::write(claude.path().join(".claude.json"), "{}").unwrap();
    std::fs::write(cwd.path().join(".mcp.json"), "{}").unwrap();
    std::fs::write(cwd.path().join("opencode.json"), "{}").unwrap();
    let roots = Roots {
        home: Some(home.path().to_owned()),
        claude_config_dir: Some(claude.path().to_owned()),
        cwd: Some(cwd.path().to_owned()),
        ..Roots::default()
    };
    let paths: Vec<PathBuf> = doctor_targets(&roots).into_iter().map(|t| t.path).collect();
    assert_eq!(
        paths,
        vec![
            home.path().join(".config/opencode/opencode.json"),
            claude.path().join(".claude.json"),
            cwd.path().join("opencode.json"),
            cwd.path().join(".mcp.json"),
        ]
    );
    // From the home directory the user and project files are the same files: listed once.
    let from_home = Roots {
        cwd: Some(home.path().join(".config/opencode")),
        claude_config_dir: None,
        ..roots
    };
    std::fs::write(home.path().join(".config/opencode/.mcp.json"), "{}").unwrap();
    let count = doctor_targets(&from_home)
        .iter()
        .filter(|t| t.path.ends_with("opencode.json"))
        .count();
    assert_eq!(count, 1);
}

#[test]
fn the_install_command_names_the_scope_and_quotes_paths() {
    let user = Target {
        client: McpInstallClient::Opencode,
        scope: Scope::User,
        path: "/x".into(),
        installable: true,
    };
    assert_eq!(
        install_command(&user, "agent"),
        "passless agent mcp install --client opencode --user --profile agent --yes"
    );
    let project = Target {
        client: McpInstallClient::ClaudeCode,
        scope: Scope::Project("/work/my project".into()),
        path: "/work/my project/.mcp.json".into(),
        installable: true,
    };
    assert_eq!(
        install_command(&project, "agent"),
        "passless agent mcp install --client claude-code --project '/work/my project' --profile agent --yes"
    );
}

#[test]
fn timestamps_are_utc_and_sortable() {
    use std::time::Duration;
    assert_eq!(utc_timestamp(Duration::from_secs(0)), "19700101T000000Z");
    assert_eq!(
        utc_timestamp(Duration::from_secs(1_700_000_000)),
        "20231114T221320Z"
    );
    // A leap day.
    assert_eq!(
        utc_timestamp(Duration::from_secs(1_709_164_800 + 86_399)),
        "20240229T235959Z"
    );
    assert_eq!(
        utc_timestamp(Duration::from_secs(1_709_251_200)),
        "20240301T000000Z"
    );
}

// ---- adding an entry --------------------------------------------------------------------------

fn added(client: McpInstallClient, text: &str) -> String {
    plan_add(client, Some(text), PASSLESS, "agent", false)
        .unwrap()
        .new_text
        .unwrap()
}

#[test]
fn an_entry_is_inserted_in_the_layout_of_the_file() {
    let claude = McpInstallClient::ClaudeCode;
    // Empty object, empty `mcpServers`, tabs, one-line files: valid JSON with the new entry, and
    // every other byte of the file as it was.
    for (text, expect_prefix) in [
        ("{}", "{\n  \"mcpServers\""),
        ("{\n}\n", "{\n  \"mcpServers\""),
        ("{\n\t\"a\": 1\n}\n", "{\n\t\"a\": 1,\n\t\"mcpServers\""),
        (
            "{\"a\": 1}",
            "{\"a\": 1, \"mcpServers\": {\"playwright\": {\"type\": \"stdio\"",
        ),
        (
            "{\n  \"mcpServers\": {}\n}\n",
            "{\n  \"mcpServers\": {\n    \"playwright\": {\n      \"type\"",
        ),
        (
            "{\n  \"mcpServers\": {\"x\": {\"command\": \"y\"}},\n  \"z\": 2\n}\n",
            "{\n  \"mcpServers\": {\"x\": {\"command\": \"y\"}, \"playwright\": {\"type\": \"stdio\"",
        ),
    ] {
        let out = added(claude, text);
        assert!(out.starts_with(expect_prefix), "{text:?} -> {out}");
        let value: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            value["mcpServers"]["playwright"]["command"], PASSLESS,
            "{out}"
        );
        let mut without = value.clone();
        without["mcpServers"]
            .as_object_mut()
            .unwrap()
            .remove("playwright");
        let before: Value = serde_json::from_str(text).unwrap();
        let mut before = before;
        before
            .as_object_mut()
            .unwrap()
            .entry("mcpServers")
            .or_insert_with(|| Value::Object(Default::default()));
        assert_eq!(without, before, "{out}");
    }
    // The trailing `"z": 2` survives untouched.
    assert!(
        added(
            claude,
            "{\n  \"mcpServers\": {\"x\": {\"command\": \"y\"}},\n  \"z\": 2\n}\n"
        )
        .ends_with("\"agent\"]}},\n  \"z\": 2\n}\n")
    );
}

#[test]
fn a_server_of_the_same_name_that_is_not_ours_is_refused() {
    for (client, text) in [
        (
            McpInstallClient::ClaudeCode,
            r#"{"mcpServers": {"playwright": {"command": "my-tool"}}}"#,
        ),
        (
            McpInstallClient::ClaudeCode,
            r#"{"mcpServers": {"playwright": {"type": "http", "url": "https://x.test"}}}"#,
        ),
        (
            McpInstallClient::Opencode,
            r#"{"mcp": {"playwright": {"type": "remote", "url": "https://x.test"}}}"#,
        ),
        (
            McpInstallClient::Opencode,
            r#"{"mcp": {"servers": {"playwright": {"type": "local", "command": ["my-tool"]}}}}"#,
        ),
    ] {
        let err = plan_add(client, Some(text), PASSLESS, "agent", false).unwrap_err();
        assert!(matches!(err, PlanError::Refused(_)), "{err}");
        assert!(err.to_string().contains("already exists"), "{err}");
    }
    // Shapes it does not dare to change.
    for text in ["[]", r#"{"mcpServers": null}"#, r#"{"mcpServers": []}"#] {
        assert!(
            matches!(
                plan_add(
                    McpInstallClient::ClaudeCode,
                    Some(text),
                    PASSLESS,
                    "agent",
                    false
                ),
                Err(PlanError::Refused(_))
            ),
            "{text}"
        );
    }
}

#[test]
fn a_new_entry_reads_back_like_a_rewrite_produces_it() {
    let out = added(
        McpInstallClient::Opencode,
        "{\n  \"mcp\": {\n    \"servers\": {}\n  }\n}\n",
    );
    let found = find_entries(
        McpInstallClient::Opencode,
        &serde_json::from_str(&out).unwrap(),
    );
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].argv,
        s(&[PASSLESS, "agent", "mcp", "playwright", "--profile", "agent"])
    );
    assert!(matches!(
        found[0].kind,
        Kind::Wrapped {
            adapter: McpAdapterKind::Playwright,
            ..
        }
    ));
    // A JSONC file is analysed, not edited.
    let jsonc = plan_add(
        McpInstallClient::ClaudeCode,
        Some("{ // c\n}"),
        PASSLESS,
        "agent",
        false,
    )
    .unwrap();
    assert!(jsonc.jsonc && jsonc.new_text.is_none() && jsonc.snippet.contains("\"playwright\""));
}

// ---- local-scope entries and shadowing --------------------------------------------------------

#[test]
fn local_scope_entries_of_the_user_file_are_found_and_rewritten() {
    let text = r#"{
  "projects": {
    "/work/app": {"mcpServers": {"playwright": {"type": "stdio", "command": "npx", "args": ["@playwright/mcp@latest"]}}},
    "/work/other": {"mcpServers": {"fs": {"command": "x"}}}
  }
}"#;
    let plan = plan(McpInstallClient::ClaudeCode, text, PASSLESS, "agent", false).unwrap();
    assert_eq!(plan.entries.len(), 1);
    let entry = &plan.entries[0].entry;
    assert_eq!(entry.local_project(), Some("/work/app"));
    assert_eq!(
        entry.location(),
        "projects[/work/app].mcpServers.playwright"
    );
    assert!(!plan.has_scope_level_entry());
    let out = plan.new_text.unwrap();
    assert!(
        out.contains("\"command\": \"/usr/bin/passless\"") || out.contains("/usr/bin/passless")
    );
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

const USER_WRAPPED: &str = r#"{"mcpServers": {"playwright": {"type": "stdio", "command": "/usr/bin/passless", "args": ["agent", "mcp", "playwright", "--profile", "p"]}}"#;

#[test]
fn a_plain_project_entry_shadows_the_user_level_passless_one() {
    let home = tempfile::tempdir().unwrap();
    let repo = home.path().join("repo");
    write(
        &home.path().join(".claude.json"),
        &format!("{USER_WRAPPED}}}"),
    );
    write(
        &repo.join(".mcp.json"),
        r#"{"mcpServers": {"playwright": {"command": "npx", "args": ["@playwright/mcp"]}}}"#,
    );
    let roots = Roots {
        home: Some(home.path().to_owned()),
        cwd: Some(repo.clone()),
        ..Roots::default()
    };
    let shadows = find_shadows(&roots);
    assert_eq!(shadows.len(), 1, "{shadows:?}");
    assert_eq!(shadows[0].scope, ShadowScope::Project);
    assert_eq!(shadows[0].file, repo.join(".mcp.json"));
    assert!(shadows[0].certain);

    // From a subdirectory the `.mcp.json` above applies, but less certainly.
    let sub = Roots {
        cwd: Some(repo.join("src")),
        ..roots.clone()
    };
    std::fs::create_dir_all(repo.join("src")).unwrap();
    assert!(!find_shadows(&sub)[0].certain);

    // A Passless entry in the repo's file is not a shadow.
    write(&repo.join(".mcp.json"), &format!("{USER_WRAPPED}}}"));
    assert!(find_shadows(&roots).is_empty());
}

#[test]
fn a_local_entry_wins_over_the_project_file_and_claude_config_dir_is_respected() {
    let home = tempfile::tempdir().unwrap();
    let repo = home.path().join("repo");
    let personal = home.path().join(".claude-personal");
    let key = repo.to_string_lossy().into_owned();
    // The default account has no Passless entry; the personal one has, and a plain local entry.
    write(&home.path().join(".claude.json"), "{}");
    write(
        &personal.join(".claude.json"),
        &format!(
            r#"{USER_WRAPPED}, "projects": {{"{key}": {{"mcpServers": {{"playwright": {{"command": "npx", "args": ["@playwright/mcp"]}}}}}}}}}}"#
        ),
    );
    write(&repo.join(".mcp.json"), &format!("{USER_WRAPPED}}}"));
    let mut roots = Roots {
        home: Some(home.path().to_owned()),
        cwd: Some(repo.clone()),
        ..Roots::default()
    };
    assert!(
        find_shadows(&roots).is_empty(),
        "the default account has nothing to shadow"
    );
    roots.claude_config_dir = Some(personal.clone());
    let shadows = find_shadows(&roots);
    assert_eq!(shadows.len(), 1, "{shadows:?}");
    assert_eq!(shadows[0].scope, ShadowScope::Local);
    assert_eq!(shadows[0].file, personal.join(".claude.json"));
}

#[test]
fn a_disabled_project_server_does_not_shadow() {
    let home = tempfile::tempdir().unwrap();
    let repo = home.path().join("repo");
    let key = repo.to_string_lossy().into_owned();
    write(
        &home.path().join(".claude.json"),
        &format!(
            r#"{USER_WRAPPED}, "projects": {{"{key}": {{"disabledMcpjsonServers": ["playwright"]}}}}}}"#
        ),
    );
    write(
        &repo.join(".mcp.json"),
        r#"{"mcpServers": {"playwright": {"command": "npx"}}}"#,
    );
    let roots = Roots {
        home: Some(home.path().to_owned()),
        cwd: Some(repo),
        ..Roots::default()
    };
    assert!(find_shadows(&roots).is_empty());
}

#[test]
fn a_project_opencode_json_may_shadow_the_global_one() {
    let home = tempfile::tempdir().unwrap();
    let repo = home.path().join("repo");
    write(
        &home.path().join(".config/opencode/opencode.json"),
        r#"{"mcp": {"servers": {"playwright": {"type": "local", "command": ["/usr/bin/passless", "agent", "mcp", "playwright", "--profile", "p"]}}}}"#,
    );
    write(
        &repo.join("opencode.json"),
        r#"{"mcp": {"playwright": {"type": "local", "command": ["npx", "@playwright/mcp"]}}}"#,
    );
    let roots = Roots {
        home: Some(home.path().to_owned()),
        cwd: Some(repo),
        ..Roots::default()
    };
    let shadows = find_shadows(&roots);
    assert_eq!(shadows.len(), 1, "{shadows:?}");
    assert_eq!(shadows[0].client, McpInstallClient::Opencode);
    assert!(
        !shadows[0].certain,
        "opencode merges several files: only a soft warning"
    );
}

#[test]
fn with_access_tool_is_written_for_playwright_entries_only() {
    let on = |argv: &[&str]| rewrite(&plain(argv), PASSLESS, "agent", &[], true).argv;
    assert_eq!(
        on(&["npx", "-y", "@playwright/mcp@latest"]),
        s(&[
            "/usr/bin/passless",
            "agent",
            "mcp",
            "playwright",
            "--profile",
            "agent",
            "--with-access-tool"
        ])
        .into_iter()
        .chain(s(&["--package", "@playwright/mcp@latest"]))
        .collect::<Vec<_>>()
    );
    // The flag goes before `--`, so it is the wrapper's and never the server's.
    let argv = on(&["npx", "@playwright/mcp", "--isolated"]);
    let flag = argv.iter().position(|a| a == "--with-access-tool").unwrap();
    let dashes = argv.iter().position(|a| a == "--").unwrap();
    assert!(flag < dashes, "{argv:?}");
    // chrome-devtools has no such tool.
    assert!(
        !on(&["npx", "chrome-devtools-mcp@latest"]).contains(&"--with-access-tool".to_string())
    );
    // Off by default.
    assert!(
        !rewrite(
            &plain(&["npx", "@playwright/mcp"]),
            PASSLESS,
            "agent",
            &[],
            false
        )
        .argv
        .contains(&"--with-access-tool".to_string())
    );
}
