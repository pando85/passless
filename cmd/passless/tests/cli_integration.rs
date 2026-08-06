use std::path::PathBuf;
use std::process::Command;

use clap::Parser;

use passless_core::{Args, Commands, OutputFormat};

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

fn run_cli(args: &[&str]) -> (String, String, i32) {
    let bin = passless_bin();
    let output = Command::new(bin)
        .args(args)
        .env("HOME", "/tmp/passless-cli-test-home")
        .output()
        .expect("failed to run passless binary");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

#[test]
fn help_exits_zero() {
    let (stdout, _, code) = run_cli(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("FIDO2 security token emulator"));
}

#[test]
fn version_exits_zero() {
    let (stdout, _, code) = run_cli(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("passless"));
}

#[test]
fn config_print_exits_zero() {
    let (stdout, _, code) = run_cli(&["config", "print"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("backend_type"));
    assert!(stdout.contains("[security]"));
    assert!(stdout.contains("[pin]"));
}

#[test]
fn config_print_contains_expected_sections() {
    let (stdout, _, code) = run_cli(&["config", "print"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("backend_type"));
    assert!(stdout.contains("[security]"));
    assert!(stdout.contains("[pin]"));
    assert!(stdout.contains("[pass]"));
    assert!(stdout.contains("[local]"));
    assert!(stdout.contains("always_uv"));
    assert!(stdout.contains("min_length"));
}

#[test]
fn unknown_subcommand_fails() {
    let (_, stderr, code) = run_cli(&["nonexistent-command"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("unrecognized") || stderr.contains("invalid") || stderr.contains("error"),
        "stderr should indicate error: {}",
        stderr
    );
}

#[test]
fn invalid_backend_type_via_cli_still_prints_config() {
    let (stdout, _, code) = run_cli(&["--backend-type", "invalid_backend", "config", "print"]);
    assert_eq!(
        code, 0,
        "config print should succeed regardless of backend type"
    );
    assert!(stdout.contains("backend_type"));
}

#[test]
fn client_subcommand_structure_parses() {
    let args = Args::try_parse_from(["passless", "client", "info"]).unwrap();
    assert!(matches!(
        args.command,
        Some(Commands::Client {
            action: passless_core::ClientAction::Info,
            ..
        })
    ));
}

#[test]
fn client_list_with_domain_filter_parses() {
    let args = Args::try_parse_from(["passless", "client", "list", "-d", "example.com"]).unwrap();
    match args.command {
        Some(Commands::Client {
            action: passless_core::ClientAction::List { rp_id },
            ..
        }) => {
            assert_eq!(rp_id.as_deref(), Some("example.com"));
        }
        _ => panic!("expected List command"),
    }
}

#[test]
fn client_output_format_json_parses() {
    let args = Args::try_parse_from(["passless", "client", "-o", "json", "info"]).unwrap();
    match args.command {
        Some(Commands::Client { output, .. }) => {
            assert_eq!(output, OutputFormat::Json);
        }
        _ => panic!("expected Client command"),
    }
}

#[test]
fn client_output_format_default_is_plain() {
    let args = Args::try_parse_from(["passless", "client", "info"]).unwrap();
    match args.command {
        Some(Commands::Client { output, .. }) => {
            assert_eq!(output, OutputFormat::Plain);
        }
        _ => panic!("expected Client command"),
    }
}

#[test]
fn client_reset_requires_double_confirm() {
    let args = Args::try_parse_from([
        "passless",
        "client",
        "reset",
        "--yes-i-really-want-to-reset-my-device",
        "--yes-i-really-want-to-reset-my-device",
    ])
    .unwrap();
    match args.command {
        Some(Commands::Client {
            action: passless_core::ClientAction::Reset { confirm },
            ..
        }) => {
            assert_eq!(confirm, 2);
        }
        _ => panic!("expected Reset command"),
    }
}

#[test]
fn client_reset_without_confirm_has_zero_count() {
    let args = Args::try_parse_from(["passless", "client", "reset"]).unwrap();
    match args.command {
        Some(Commands::Client {
            action: passless_core::ClientAction::Reset { confirm },
            ..
        }) => {
            assert_eq!(confirm, 0);
        }
        _ => panic!("expected Reset command"),
    }
}

#[test]
fn client_pin_set_parses() {
    let args = Args::try_parse_from(["passless", "client", "pin", "set", "1234"]).unwrap();
    match args.command {
        Some(Commands::Client {
            action:
                passless_core::ClientAction::Pin {
                    action: passless_core::PinAction::Set { pin },
                },
            ..
        }) => {
            assert_eq!(pin, "1234");
        }
        _ => panic!("expected Pin Set command"),
    }
}

#[test]
fn client_pin_change_parses() {
    let args =
        Args::try_parse_from(["passless", "client", "pin", "change", "1234", "5678"]).unwrap();
    match args.command {
        Some(Commands::Client {
            action:
                passless_core::ClientAction::Pin {
                    action: passless_core::PinAction::Change { old_pin, new_pin },
                },
            ..
        }) => {
            assert_eq!(old_pin, "1234");
            assert_eq!(new_pin, "5678");
        }
        _ => panic!("expected Pin Change command"),
    }
}

#[test]
fn client_device_flag_parses() {
    let args = Args::try_parse_from(["passless", "client", "-D", "0", "info"]).unwrap();
    match args.command {
        Some(Commands::Client { device, .. }) => {
            assert_eq!(device.as_deref(), Some("0"));
        }
        _ => panic!("expected Client command"),
    }
}

#[test]
fn output_format_from_str() {
    assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
    assert_eq!(
        "plain".parse::<OutputFormat>().unwrap(),
        OutputFormat::Plain
    );
    assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
    assert!("invalid".parse::<OutputFormat>().is_err());
}

#[test]
fn error_format_cli_storage_error() {
    let err = passless_core::Error::Storage("disk full".into());
    let formatted = err.format_cli();
    assert!(formatted.contains("Storage error"));
    assert!(formatted.contains("disk full"));
}

#[test]
fn error_format_cli_config_error() {
    let err = passless_core::Error::Config("bad value".into());
    let formatted = err.format_cli();
    assert!(formatted.contains("Configuration error"));
    assert!(formatted.contains("bad value"));
}

#[test]
fn error_format_cli_cancelled() {
    let err = passless_core::Error::Cancelled;
    let formatted = err.format_cli();
    assert!(formatted.contains("cancelled"));
}

#[test]
fn no_autonomous_mode_subcommand_exists() {
    use clap::CommandFactory;
    let app = Args::command();
    let subcommands: Vec<&str> = app.get_subcommands().map(|c| c.get_name()).collect();
    assert!(
        !subcommands.contains(&"autonomous"),
        "autonomous mode should not exist as a subcommand"
    );
    assert!(
        !subcommands.contains(&"daemon"),
        "daemon mode should not exist as a subcommand"
    );
}

#[test]
fn client_rename_parses_with_both_names() {
    let args = Args::try_parse_from([
        "passless", "client", "rename", "aabbccdd", "-u", "newuser", "-n", "New Name",
    ])
    .unwrap();
    match args.command {
        Some(Commands::Client {
            action:
                passless_core::ClientAction::Rename {
                    credential_id,
                    user_name,
                    display_name,
                },
            ..
        }) => {
            assert_eq!(credential_id, "aabbccdd");
            assert_eq!(user_name.as_deref(), Some("newuser"));
            assert_eq!(display_name.as_deref(), Some("New Name"));
        }
        _ => panic!("expected Rename command"),
    }
}

#[test]
fn client_show_parses_credential_id() {
    let args = Args::try_parse_from(["passless", "client", "show", "deadbeef"]).unwrap();
    match args.command {
        Some(Commands::Client {
            action: passless_core::ClientAction::Show { credential_id },
            ..
        }) => {
            assert_eq!(credential_id, "deadbeef");
        }
        _ => panic!("expected Show command"),
    }
}
