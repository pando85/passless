//! Integration test for instance lock (concurrent daemon detection)
//!
//! Verifies that a second daemon targeting the same backend state path
//! is rejected immediately with a clear error message.
//!
//! These tests require the uhid kernel module and proper permissions.
//! Run with: `make test-e2e` or `cargo test -- --ignored --test-threads=1`

mod harness;

use harness::{AuthenticatorHarness, LocalBackend};

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;

#[test]
#[ignore]
fn test_duplicate_daemon_same_backend_is_rejected() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let backend_path = temp_dir.path().to_path_buf();

    let mut harness1 =
        AuthenticatorHarness::new(Box::new(LocalBackend::with_path(backend_path.clone())));
    harness1.start().expect("First daemon should start");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_passless"));
    cmd.args([
        "--backend-type",
        "local",
        "--local-path",
        &backend_path.display().to_string(),
        "-v",
    ])
    .env("PASSLESS_CONFIG", temp_dir.path().join("config.toml"))
    .env("PASSLESS_E2E_AUTO_ACCEPT_UV", "1")
    .env("PASSLESS_E2E_AUTO_ACCEPT_STORAGE", "1")
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn second daemon");

    let stderr = child.stderr.take().expect("Failed to take stderr");
    let stderr_lines: Vec<String> = BufReader::new(stderr)
        .lines()
        .map_while(Result::ok)
        .collect();

    let status = child.wait().expect("Failed to wait for second daemon");

    assert!(
        !status.success(),
        "Second daemon should exit with non-zero status"
    );

    let stderr_text = stderr_lines.join("\n");
    assert!(
        stderr_text.contains("already using backend state")
            || stderr_text.contains("AlreadyRunning"),
        "stderr should mention duplicate instance. Got: {}",
        stderr_text
    );

    drop(harness1);
}

#[test]
#[ignore]
fn test_daemons_with_different_backends_can_run_concurrently() {
    let temp_dir1 = TempDir::new().expect("Failed to create temp dir 1");
    let temp_dir2 = TempDir::new().expect("Failed to create temp dir 2");

    let mut harness1 = AuthenticatorHarness::new(Box::new(LocalBackend::with_path(
        temp_dir1.path().to_path_buf(),
    )));
    harness1.start().expect("First daemon should start");

    let mut harness2 = AuthenticatorHarness::new(Box::new(LocalBackend::with_path(
        temp_dir2.path().to_path_buf(),
    )));
    harness2
        .start_and_wait_for_device_count(2)
        .expect("Second daemon with different backend should start");

    drop(harness1);
    drop(harness2);
}

#[test]
#[ignore]
fn test_lock_released_after_daemon_stops() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let backend_path = temp_dir.path().to_path_buf();

    let mut harness =
        AuthenticatorHarness::new(Box::new(LocalBackend::with_path(backend_path.clone())));
    harness.start().expect("First daemon should start");

    harness.stop();

    std::thread::sleep(Duration::from_millis(500));

    let mut harness2 =
        AuthenticatorHarness::new(Box::new(LocalBackend::with_path(backend_path.clone())));
    harness2
        .start()
        .expect("New daemon should start after previous one stopped");

    drop(harness2);
}
