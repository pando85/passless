//! Integration tests for TPM capability checks and downgrade protection.

#![cfg(feature = "tpm")]

use passless_rs::storage::tpm::portable::parent;
use passless_rs::storage::tpm::portable::provider::validate_record_version;
use passless_rs::storage::tpm::portable::{PortableParent, TpmCredentialKeyProvider};
use soft_fido2_ctap::key_provider::{
    CredentialKey, CredentialKeyError, CredentialKeyProvider, CredentialKeyProviderId,
};

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
        let _tcti_kind = std::env::var("PASSLESS_TEST_TCTI").unwrap_or_else(|_| "swtpm".into());
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
fn test_capability_check_es256_supported() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24612, 24611));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");

    let seed = [0x42u8; 32];
    parent.provision(&seed).expect("provision");

    let provider = TpmCredentialKeyProvider::new(storage_dir.clone(), Some(swtpm.tcti()))
        .expect("create provider");

    assert!(
        provider.supports_algorithm(-7),
        "swtpm must report ES256 (COSE -7) as supported via TPM2_GetCapability"
    );

    let generated = provider.generate(-7).expect("generate key on capable TPM");
    assert_eq!(generated.cose_public_key.len(), 65);
    assert_eq!(generated.cose_public_key[0], 0x04);
}

#[test]
fn test_downgrade_protection_rejects_newer_version() {
    let _ = env_logger::builder().is_test(true).try_init();

    let result = validate_record_version(parent::FORMAT_VERSION);
    assert!(result.is_ok(), "current version must be accepted");

    let newer_version = parent::FORMAT_VERSION + 1;
    let result = validate_record_version(newer_version);
    assert_eq!(
        result,
        Err(CredentialKeyError::UnsupportedFormatVersion),
        "newer version {} must be refused with UnsupportedFormatVersion",
        newer_version
    );

    let result = validate_record_version(0);
    assert_eq!(
        result,
        Err(CredentialKeyError::UnsupportedFormatVersion),
        "version 0 (unknown) must be refused with UnsupportedFormatVersion"
    );

    let far_future_version = 9999;
    let result = validate_record_version(far_future_version);
    assert_eq!(
        result,
        Err(CredentialKeyError::UnsupportedFormatVersion),
        "far-future version must be refused"
    );
}

#[test]
fn test_downgrade_protection_sign_rejects_newer_key() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24622, 24621));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");

    let seed = [0x42u8; 32];
    parent.provision(&seed).expect("provision");

    let provider = TpmCredentialKeyProvider::new(storage_dir.clone(), Some(swtpm.tcti()))
        .expect("create provider");

    let generated = provider.generate(-7).expect("generate key");

    let newer_version_key = CredentialKey::new(
        CredentialKeyProviderId::new(b"tpm-portable-v1"),
        parent::FORMAT_VERSION + 1,
        generated.key.material.clone(),
    );

    let result = provider.sign(&newer_version_key, -7, b"test");
    assert_eq!(
        result,
        Err(CredentialKeyError::UnsupportedFormatVersion),
        "sign with newer-version key must return UnsupportedFormatVersion"
    );

    let zero_version_key = CredentialKey::new(
        CredentialKeyProviderId::new(b"tpm-portable-v1"),
        0,
        generated.key.material.clone(),
    );

    let result = provider.sign(&zero_version_key, -7, b"test");
    assert_eq!(
        result,
        Err(CredentialKeyError::UnsupportedFormatVersion),
        "sign with version-0 key must return UnsupportedFormatVersion"
    );
}
