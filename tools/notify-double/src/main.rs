use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use notify_double::cli::{self, Cli};
use notify_double::server::NotificationDouble;
use notify_double::{LogWriter, OBJECT_PATH, WELL_KNOWN_NAME};

use tokio::signal::unix::{SignalKind, signal};
use zbus::connection::Builder;

async fn run(cli: Cli) -> Result<(), String> {
    let log = Arc::new(
        LogWriter::open(&cli.log).map_err(|e| format!("cannot open log {:?}: {e}", cli.log))?,
    );
    let service = NotificationDouble::new(cli.config, Arc::clone(&log));

    let conn = Builder::session()
        .name(WELL_KNOWN_NAME)
        // zbus defaults to REPLACE_EXISTING; a taken name must be an error, not a takeover.
        .replace_existing_names(false)
        .allow_name_replacements(false)
        .serve_at(OBJECT_PATH, service)
        .build()
        .await
        .map_err(|e| format!("cannot acquire {WELL_KNOWN_NAME} (already taken?): {e}"))?;

    if let Some(path) = &cli.ready_file {
        let unique = conn
            .unique_name()
            .map(|n| n.to_string())
            .ok_or("connection has no unique name")?;
        write_ready_file(path, &unique)?;
    }

    let mut sigterm = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut sigint = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    // Every event is flushed when written; closing releases the bus name.
    let _ = conn.close().await;
    Ok(())
}

fn write_ready_file(path: &Path, unique: &str) -> Result<(), String> {
    let mut tmp: PathBuf = path.to_path_buf();
    tmp.as_mut_os_string().push(".tmp");
    fs::write(&tmp, format!("{unique}\n"))
        .and_then(|()| fs::rename(&tmp, path))
        .map_err(|e| format!("cannot write ready file {path:?}: {e}"))
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match cli::parse(
        std::env::args().skip(1),
        std::env::var("NOTIFY_DOUBLE_SCRIPT").ok(),
    ) {
        Ok(cli) => cli,
        Err(msg) => {
            eprintln!("notify-double: {msg}");
            return ExitCode::from(2);
        }
    };
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("notify-double: {msg}");
            ExitCode::FAILURE
        }
    }
}
