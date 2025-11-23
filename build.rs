use std::env;
use std::fs;
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate_to};

/// Passless - Software FIDO2 Authenticator (wrapper for subcommands)
#[derive(Parser, Debug)]
#[command(
    name = "passless",
    author = "Pando85 <pando855@gmail.com>",
    version = env!("CARGO_PKG_VERSION"),
    about = "FIDO2 security token emulator"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Subcommands for passless
#[derive(Subcommand, Debug)]
enum Commands {
    /// Configuration management commands
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

/// Configuration actions
#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Print the default configuration in TOML format
    Print,
}

fn main() {
    // Generate shell completions at build time
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let completions_dir = PathBuf::from(&out_dir).join("completions");
    fs::create_dir_all(&completions_dir).unwrap();

    let mut cmd = Cli::command();

    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::Elvish] {
        generate_to(shell, &mut cmd, "passless", &completions_dir).unwrap();
    }

    println!(
        "cargo:warning=Shell completions generated in {:?}",
        completions_dir
    );
}
