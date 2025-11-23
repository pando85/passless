use std::path::PathBuf;
use std::{env, fs};

use clap::CommandFactory;
use clap_complete::{Shell, generate_to};

fn main() {
    // Generate shell completions at build time
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let completions_dir = PathBuf::from(&out_dir).join("completions");
    fs::create_dir_all(&completions_dir).unwrap();

    // Use the actual Args struct from passless-core to ensure completions match the runtime CLI
    let mut cmd = passless_core::Args::command();

    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::Elvish] {
        generate_to(shell, &mut cmd, "passless", &completions_dir).unwrap();
    }

    println!(
        "cargo:warning=Shell completions generated in {:?}",
        completions_dir
    );
}
