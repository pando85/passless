//! Test configuration with clap-serde-derive to validate the pattern

use clap::{Parser};
use clap_serde_derive::{ClapSerde};
use serde::{Deserialize, Serialize};

/// Simple backend config
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize)]
struct BackendConfig {
    #[arg(long = "backend-path", env = "TEST_BACKEND_PATH")]
    #[default("./data".to_string())]
    path: String,

    #[arg(long = "backend-name")]
    #[default("test".to_string())]
    name: String,
}

/// Security config
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize)]
struct SecurityConfig {
    #[arg(long = "enable-mlock")]
    #[default(true)]
    enable_mlock: bool,

    #[arg(long = "verbose")]
    #[default(false)]
    verbose: bool,
}

/// Main config - NO Clone/Debug here because it has #[clap_serde] fields
#[derive(ClapSerde, Serialize, Deserialize)]
struct AppConfig {
    #[arg(short = 't', long = "type")]
    #[default("local".to_string())]
    backend_type: String,

    #[clap_serde]
    #[command(flatten)]
    backend: BackendConfig,

    #[clap_serde]
    #[command(flatten)]
    security: SecurityConfig,
}

/// CLI Args
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Config file path
    #[arg(short, long)]
    config: Option<std::path::PathBuf>,

    #[command(flatten)]
    app_config: <AppConfig as ClapSerde>::Opt,
}

fn main() {
    // Test 1: Parse from CLI only (with defaults)
    println!("=== Test 1: CLI only (defaults) ===");
    let mut args = Args::parse_from(["test_config"]);
    let config = AppConfig::from(&mut args.app_config);
    println!("backend_type: {}", config.backend_type);
    println!("backend.path: {}", config.backend.path);
    println!("backend.name: {}", config.backend.name);
    println!("security.enable_mlock: {}", config.security.enable_mlock);
    println!("security.verbose: {}", config.security.verbose);
    println!("TOML:\n{}", toml::to_string_pretty(&config).unwrap());

    // Test 2: Parse from CLI with some args
    println!("\n=== Test 2: CLI with args ===");
    let mut args = Args::parse_from([
        "test_config",
        "--type",
        "remote",
        "--backend-path",
        "/tmp/test",
        "--verbose=true",
    ]);
    let config = AppConfig::from(&mut args.app_config);
    println!("backend_type: {}", config.backend_type);
    println!("backend.path: {}", config.backend.path);
    println!("security.verbose: {}", config.security.verbose);

    // Test 3: Load from TOML + merge CLI
    println!("\n=== Test 3: TOML + CLI merge ===");
    let toml_str = r#"
backend_type = "tpm"

[backend]
path = "/var/data"
name = "production"

[security]
enable_mlock = false
verbose = true
"#;

    let file_config: AppConfig = toml::from_str(toml_str).expect("Failed to parse TOML");
    println!("From file - backend_type: {}", file_config.backend_type);
    println!("From file - backend.path: {}", file_config.backend.path);

    // Merge with CLI args (CLI takes precedence)
    let mut args = Args::parse_from(["test_config", "--type", "override"]);
    let merged = file_config.merge(&mut args.app_config);
    println!("Merged - backend_type: {}", merged.backend_type);
    println!("Merged - backend.path: {}", merged.backend.path);
    println!(
        "backend_type should be 'override': {}",
        merged.backend_type == "override"
    );
    println!(
        "backend.path should be '/var/data': {}",
        merged.backend.path == "/var/data"
    );
}
