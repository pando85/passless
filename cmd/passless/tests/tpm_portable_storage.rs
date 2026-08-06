//! Integration tests for TPM portable metadata sealing using swtpm.
//!
//! Verifies that credential records sealed in portable mode can be unsealed
//! on a different TPM provisioned from the same recovery seed.

#![cfg(feature = "tpm")]

use passless_rs::storage::TpmStorageAdapter;
use passless_rs::storage::tpm::portable::PortableParent;

use std::process::{Child, Command};
use std::time::Duration;

struct SwtpmInstance {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl SwtpmInstance {
    fn new(port_pair: (u16, u16)) -> Self {
        let (ctrl_port, server_port) = port_pair;
        let dir = tempfile::tempdir().expect("create temp dir");

        let flags = std::env::var("PASSLESS_TEST_SWTPM_FLAGS")
            .unwrap_or_else(|_| "not-need-init,startup-clear".into());
        let no_ctrl = std::env::var("PASSLESS_TEST_NO_CTRL").is_ok();
        let use_unix = std::env::var("PASSLESS_TEST_UNIX_SOCKET").is_ok();

        let mut cmd = Command::new("swtpm");
        cmd.arg("socket")
            .arg("--tpmstate")
            .arg(format!("dir={}", dir.path().display()))
            .arg("--tpm2");

        if !no_ctrl {
            cmd.arg("--ctrl")
                .arg(format!("type=tcp,port={}", ctrl_port));
        }

        if use_unix {
            let sock_path = dir.path().join("swtpm.sock");
            cmd.arg("--server")
                .arg(format!("type=unixio,path={}", sock_path.display()));
        } else {
            cmd.arg("--server")
                .arg(format!("type=tcp,port={}", server_port));
        }

        if !flags.is_empty() {
            cmd.arg("--flags").arg(&flags);
        }

        let pid_file = dir.path().join("swtpm.pid");
        cmd.arg("--pid").arg(format!("file={}", pid_file.display()));

        cmd.arg("--daemon");

        let child = cmd.spawn().expect("spawn swtpm");

        let mut ready = false;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(50));
            if use_unix {
                let sock_path = dir.path().join("swtpm.sock");
                if std::os::unix::net::UnixStream::connect(&sock_path).is_ok() {
                    ready = true;
                    break;
                }
            } else if std::net::TcpStream::connect(("127.0.0.1", server_port)).is_ok() {
                ready = true;
                break;
            }
        }

        if !ready {
            panic!("swtpm failed to start");
        }

        if !no_ctrl {
            for _ in 0..50 {
                std::thread::sleep(Duration::from_millis(50));
                if std::net::TcpStream::connect(("127.0.0.1", ctrl_port)).is_ok() {
                    break;
                }
            }
        }

        std::thread::sleep(Duration::from_millis(200));

        Self {
            child,
            port: server_port,
            _dir: dir,
        }
    }

    fn tcti(&self) -> String {
        let tcti_kind = std::env::var("PASSLESS_TEST_TCTI").unwrap_or_else(|_| "swtpm".into());
        match tcti_kind.as_str() {
            "mssim" => format!("mssim:host=127.0.0.1,port={}", self.port),
            _ => format!("swtpm:host=127.0.0.1,port={}", self.port),
        }
    }
}

impl Drop for SwtpmInstance {
    fn drop(&mut self) {
        if let Ok(pid_str) = std::fs::read_to_string(self._dir.path().join("swtpm.pid"))
            && let Ok(pid) = pid_str.trim().parse::<u32>()
        {
            let _ = Command::new("kill").arg(pid.to_string()).status();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn test_tpm_portable_metadata_sealing() {
    let _ = env_logger::builder().is_test(true).try_init();

    let seed = [0x42u8; 32];
    let test_data = b"secret credential metadata payload";

    // TPM A: provision and seal
    let swtpm_a = SwtpmInstance::new((24412, 24411));
    let dir_a = tempfile::tempdir().expect("create temp dir");
    let storage_dir_a = dir_a.path().to_path_buf();

    let parent_a =
        PortableParent::new(storage_dir_a.clone(), Some(swtpm_a.tcti())).expect("create parent A");
    parent_a.provision(&seed).expect("provision A");

    // Create the portable_parent.json marker so new_portable succeeds
    // (PortableParent::provision already writes it)
    let adapter_a =
        TpmStorageAdapter::new_portable(storage_dir_a.clone(), Some(swtpm_a.tcti()), true)
            .expect("create portable adapter A");

    let sealed_blob = adapter_a.seal_data(test_data, b"").expect("seal data on A");

    // TPM B: provision with SAME seed, unseal
    let swtpm_b = SwtpmInstance::new((24423, 24422));
    let dir_b = tempfile::tempdir().expect("create temp dir");
    let storage_dir_b = dir_b.path().to_path_buf();

    let parent_b =
        PortableParent::new(storage_dir_b.clone(), Some(swtpm_b.tcti())).expect("create parent B");
    parent_b.provision(&seed).expect("provision B");

    let adapter_b =
        TpmStorageAdapter::new_portable(storage_dir_b.clone(), Some(swtpm_b.tcti()), true)
            .expect("create portable adapter B");

    let unsealed = adapter_b
        .unseal_data(&sealed_blob, b"")
        .expect("unseal data on B");
    assert_eq!(unsealed, test_data);

    // TPM C: provision with DIFFERENT seed, unseal must fail
    let swtpm_c = SwtpmInstance::new((24433, 24432));
    let dir_c = tempfile::tempdir().expect("create temp dir");
    let storage_dir_c = dir_c.path().to_path_buf();

    let parent_c =
        PortableParent::new(storage_dir_c.clone(), Some(swtpm_c.tcti())).expect("create parent C");
    let different_seed = [0x99u8; 32];
    parent_c.provision(&different_seed).expect("provision C");

    let adapter_c =
        TpmStorageAdapter::new_portable(storage_dir_c.clone(), Some(swtpm_c.tcti()), true)
            .expect("create portable adapter C");

    let result = adapter_c.unseal_data(&sealed_blob, b"");
    assert!(result.is_err(), "unseal on different-seed TPM must fail");
}
