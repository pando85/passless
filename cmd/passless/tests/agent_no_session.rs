//! Principal commands run outside an agent session: they need the session's control socket on
//! fd 3, and say so instead of naming the descriptor.
#![cfg(feature = "agent")]

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use tempfile::tempdir;

fn passless_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_passless"))
}

/// Run `passless agent <args>` with nothing on fd 3 and no daemon.
fn run_outside_a_session(args: &[&str]) -> (String, String, i32) {
    let home = tempdir().unwrap();
    let runtime = tempdir().unwrap();
    let mut command = Command::new(passless_bin());
    command
        .arg("agent")
        .args(args)
        .env("HOME", home.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env_remove("PASSLESS_AGENT_RUNTIME_DIR")
        .env_remove("PASSLESS_CONFIG");
    // SAFETY: only async-signal-safe `close` runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            libc::close(3);
            Ok(())
        });
    }
    let output = command.output().expect("failed to run passless");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

#[test]
fn agent_doctor_outside_a_session_says_to_run_it_inside_one() {
    let (stdout, stderr, code) = run_outside_a_session(&["doctor", "--profile", "coding"]);
    assert_ne!(code, 0, "stdout: {stdout}");
    assert!(!stderr.contains("CONTROL_FD"), "{stderr}");
    assert!(stderr.contains("inside an agent session"), "{stderr}");
    assert!(
        stderr.contains(
            "passless agent run --profile coding -- passless agent doctor --profile coding"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains("passless agent-admin profile check coding"),
        "{stderr}"
    );
}
