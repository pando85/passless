//! Integration tests for TPM portable PIN storage using swtpm.

#![cfg(feature = "tpm")]

use passless_rs::pin_storage::PinStorage;
use passless_rs::pin_storage::tpm::TpmPinStorage;
use passless_rs::storage::tpm::portable::PortableParent;
use passless_rs::storage::tpm::portable::build_portable_bundle;
use soft_fido2::PinState;

use std::process::{Child, Command};
use std::time::Duration;

fn make_secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create temp dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("set secure permissions");
    }
    dir
}

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

fn make_pin_state(pin: &str) -> PinState {
    use soft_fido2_ctap::SecPinHash;
    let mut hash = [0u8; 32];
    let pin_bytes = pin.as_bytes();
    hash[..pin_bytes.len()].copy_from_slice(pin_bytes);
    PinState {
        pin_hash: Some(SecPinHash::new(hash)),
        retries: 8,
        uv_retries: 8,
        min_pin_length: 4,
        version: 1,
        force_pin_change: false,
        locked_until: None,
        credential_wrapping_generation: 0,
    }
}

#[test]
fn test_portable_pin_storage_roundtrip_across_tpm() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm_a = SwtpmInstance::new((24712, 24711));
    let dir_a = make_secure_tempdir();
    let storage_dir_a = dir_a.path().to_path_buf();

    let parent_a =
        PortableParent::new(storage_dir_a.clone(), Some(swtpm_a.tcti())).expect("create parent A");
    let seed = [0x42u8; 32];
    parent_a.provision(&seed).expect("provision A");

    let pin_storage_a = TpmPinStorage::new_portable(storage_dir_a.clone(), Some(swtpm_a.tcti()));
    let state = make_pin_state("1234");
    pin_storage_a.save_pin_state(&state).expect("save on A");

    let sealed_path = storage_dir_a.join("pin_state.json.tpm.portable");
    assert!(sealed_path.exists(), "portable sealed file must exist");
    let sealed_bytes = std::fs::read(&sealed_path).expect("read sealed blob");

    let swtpm_b = SwtpmInstance::new((24723, 24722));
    let dir_b = make_secure_tempdir();
    let storage_dir_b = dir_b.path().to_path_buf();

    let parent_b =
        PortableParent::new(storage_dir_b.clone(), Some(swtpm_b.tcti())).expect("create parent B");
    parent_b.provision(&seed).expect("provision B");

    let portable_sealed_path = storage_dir_b.join("pin_state.json.tpm.portable");
    std::fs::write(&portable_sealed_path, &sealed_bytes).expect("copy sealed blob to B");

    let pin_storage_b = TpmPinStorage::new_portable(storage_dir_b.clone(), Some(swtpm_b.tcti()));
    let loaded = pin_storage_b.load_pin_state().expect("unseal on B");

    assert!(loaded.is_pin_set());
    assert_eq!(loaded.retries, 8);
    assert_eq!(loaded.min_pin_length, 4);
    assert_eq!(loaded.version, 1);
    assert_eq!(
        loaded.pin_hash.as_ref().map(|h| h.as_array().to_vec()),
        state.pin_hash.as_ref().map(|h| h.as_array().to_vec())
    );
}

#[test]
fn test_portable_pin_storage_missing_parent() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24734, 24733));
    let dir = make_secure_tempdir();
    let storage_dir = dir.path().to_path_buf();

    let pin_storage = TpmPinStorage::new_portable(storage_dir.clone(), Some(swtpm.tcti()));
    let state = make_pin_state("1234");
    let result = pin_storage.save_pin_state(&state);
    assert!(result.is_err(), "should fail without provisioned parent");
}

#[test]
fn test_legacy_pin_storage_still_works() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24745, 24744));
    let dir = make_secure_tempdir();
    let storage_dir = dir.path().to_path_buf();

    let pin_storage = TpmPinStorage::new(storage_dir.clone(), Some(swtpm.tcti()));
    let state = make_pin_state("5678");
    pin_storage.save_pin_state(&state).expect("save legacy");

    let loaded = pin_storage.load_pin_state().expect("load legacy");
    assert!(loaded.is_pin_set());
    assert_eq!(loaded.retries, 8);
    assert_eq!(
        loaded.pin_hash.as_ref().map(|h| h.as_array().to_vec()),
        state.pin_hash.as_ref().map(|h| h.as_array().to_vec())
    );
}

#[test]
fn test_portable_and_legacy_use_different_files() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24756, 24755));
    let dir = make_secure_tempdir();
    let storage_dir = dir.path().to_path_buf();

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");
    let seed = [0x42u8; 32];
    parent.provision(&seed).expect("provision");

    let legacy = TpmPinStorage::new(storage_dir.clone(), Some(swtpm.tcti()));
    let portable = TpmPinStorage::new_portable(storage_dir.clone(), Some(swtpm.tcti()));

    let legacy_state = make_pin_state("1111");
    let portable_state = make_pin_state("2222");

    legacy.save_pin_state(&legacy_state).expect("save legacy");
    portable
        .save_pin_state(&portable_state)
        .expect("save portable");

    let legacy_path = storage_dir.join("pin_state.json.tpm");
    let portable_path = storage_dir.join("pin_state.json.tpm.portable");
    assert!(legacy_path.exists());
    assert!(portable_path.exists());

    let loaded_legacy = legacy.load_pin_state().expect("load legacy");
    let loaded_portable = portable.load_pin_state().expect("load portable");

    assert_eq!(
        loaded_legacy
            .pin_hash
            .as_ref()
            .map(|h| h.as_array().to_vec()),
        legacy_state
            .pin_hash
            .as_ref()
            .map(|h| h.as_array().to_vec())
    );
    assert_eq!(
        loaded_portable
            .pin_hash
            .as_ref()
            .map(|h| h.as_array().to_vec()),
        portable_state
            .pin_hash
            .as_ref()
            .map(|h| h.as_array().to_vec())
    );
}

#[test]
fn portable_bundle_wiring_uses_portable_pin_file() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((25034, 25033));
    let dir = make_secure_tempdir();
    let storage_dir = dir.path().to_path_buf();

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");
    let seed = [0x55u8; 32];
    parent.provision(&seed).expect("provision");

    let tcti = Some(swtpm.tcti());

    let (_provider, _storage, pin_storage) =
        build_portable_bundle(storage_dir.clone(), tcti, true).expect("build portable bundle");

    let state = make_pin_state("9876");
    pin_storage.save_pin_state(&state).expect("save pin state");

    let portable_pin_path = storage_dir.join("pin_state.json.tpm.portable");
    let legacy_pin_path = storage_dir.join("pin_state.json.tpm");

    assert!(
        portable_pin_path.exists(),
        "portable bundle must write pin_state.json.tpm.portable"
    );
    assert!(
        !legacy_pin_path.exists(),
        "portable bundle must NOT write legacy pin_state.json.tpm"
    );

    let loaded = pin_storage.load_pin_state().expect("load pin state");
    assert!(loaded.is_pin_set());
    assert_eq!(
        loaded.pin_hash.as_ref().map(|h| h.as_array().to_vec()),
        state.pin_hash.as_ref().map(|h| h.as_array().to_vec())
    );
}
