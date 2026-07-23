//! Integration tests for TPM portable credential key provider using swtpm.

#![cfg(feature = "tpm")]

use passless_rs::storage::tpm::portable::{PortableParent, TpmCredentialKeyProvider};
use soft_fido2_ctap::key_provider::CredentialKeyProvider;

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

        // Wait for swtpm to start listening
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

        // Also wait for ctrl port to be ready
        if !no_ctrl {
            for _ in 0..50 {
                std::thread::sleep(Duration::from_millis(50));
                if std::net::TcpStream::connect(("127.0.0.1", ctrl_port)).is_ok() {
                    break;
                }
            }
        }

        // Additional wait for TPM to fully initialize
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
fn test_tpm_portable_provision_and_sign() {
    let _ = env_logger::builder().is_test(true).try_init();
    // Use unique port pairs to avoid conflicts
    // Note: swtpm TCTI expects control port to be server_port + 1
    let swtpm_a = SwtpmInstance::new((23312, 23311));
    let dir_a = tempfile::tempdir().expect("create temp dir");
    let storage_dir_a = dir_a.path().to_path_buf();

    let parent_a =
        PortableParent::new(storage_dir_a.clone(), Some(swtpm_a.tcti())).expect("create parent A");

    let seed = [0x42u8; 32];
    parent_a.provision(&seed).expect("provision A");

    assert!(parent_a.is_provisioned());
    let metadata = parent_a.load_metadata().expect("load metadata");
    parent_a.verify_parent(&metadata).expect("verify parent");

    let provider_a = TpmCredentialKeyProvider::new(storage_dir_a.clone(), Some(swtpm_a.tcti()))
        .expect("create provider A");

    let generated = provider_a.generate(-7).expect("generate key");

    assert_eq!(generated.cose_public_key.len(), 65);
    assert_eq!(generated.cose_public_key[0], 0x04);

    let message = b"test message to sign";
    let signature = provider_a
        .sign(&generated.key, -7, message)
        .expect("sign message");

    assert!(!signature.is_empty());
    assert_eq!(signature[0], 0x30);

    use p256::PublicKey;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    let public_key =
        PublicKey::from_sec1_bytes(&generated.cose_public_key).expect("valid public key");
    let verifying_key = VerifyingKey::from(&public_key);

    let sig = Signature::from_der(&signature).expect("parse DER signature");
    verifying_key
        .verify(message, &sig)
        .expect("verify signature");

    let swtpm_b = SwtpmInstance::new((23323, 23322));
    let dir_b = tempfile::tempdir().expect("create temp dir");
    let storage_dir_b = dir_b.path().to_path_buf();

    let parent_b =
        PortableParent::new(storage_dir_b.clone(), Some(swtpm_b.tcti())).expect("create parent B");

    parent_b.provision(&seed).expect("provision B");

    let provider_b = TpmCredentialKeyProvider::new(storage_dir_b.clone(), Some(swtpm_b.tcti()))
        .expect("create provider B");

    let signature_b = provider_b
        .sign(&generated.key, -7, message)
        .expect("sign on B");

    let sig_b = Signature::from_der(&signature_b).expect("parse DER signature B");
    verifying_key
        .verify(message, &sig_b)
        .expect("verify signature from B");

    let swtpm_c = SwtpmInstance::new((23333, 23332));
    let dir_c = tempfile::tempdir().expect("create temp dir");
    let storage_dir_c = dir_c.path().to_path_buf();

    let parent_c =
        PortableParent::new(storage_dir_c.clone(), Some(swtpm_c.tcti())).expect("create parent C");

    let different_seed = [0x99u8; 32];
    parent_c.provision(&different_seed).expect("provision C");

    let provider_c = TpmCredentialKeyProvider::new(storage_dir_c.clone(), Some(swtpm_c.tcti()))
        .expect("create provider C");

    let result = provider_c.sign(&generated.key, -7, message);
    assert!(result.is_err());

    let mut tampered_material = generated.key.material.as_slice().to_vec();
    if let Some(byte) = tampered_material.get_mut(10) {
        *byte ^= 0xFF;
    }

    let tampered_key = soft_fido2_ctap::key_provider::CredentialKey::new(
        soft_fido2_ctap::key_provider::CredentialKeyProviderId::new(b"tpm-portable-v1"),
        1,
        soft_fido2_ctap::SecBytes::from_slice(&tampered_material),
    );

    let result = provider_a.sign(&tampered_key, -7, message);
    assert!(result.is_err());
}

#[test]
fn test_tpm_portable_import_existing_key() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((23412, 23411));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");

    let seed = [0x42u8; 32];
    parent.provision(&seed).expect("provision");
    assert!(parent.is_provisioned());

    let provider = TpmCredentialKeyProvider::new(storage_dir.clone(), Some(swtpm.tcti()))
        .expect("create provider");

    let test_scalar: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, 0x82, 0x93, 0xA4, 0xB5, 0xC6, 0xD7,
        0xE8, 0xF9,
    ];

    let (expected_x, expected_y) =
        passless_rs::storage::tpm::portable::provider::compute_public_from_scalar(&test_scalar)
            .expect("compute public from scalar");

    let mut expected_cose = vec![0x04];
    expected_cose.extend_from_slice(&expected_x);
    expected_cose.extend_from_slice(&expected_y);

    let imported = provider
        .import_existing_es256_key(&test_scalar)
        .expect("import existing key");

    assert_eq!(imported.cose_public_key.len(), 65);
    assert_eq!(imported.cose_public_key[0], 0x04);
    assert_eq!(imported.cose_public_key, expected_cose);

    let key_material: serde_json::Value =
        serde_json::from_slice(imported.key.material.as_slice()).expect("parse material");
    let public_blob: Vec<u8> =
        serde_json::from_value(key_material["public_blob"].clone()).expect("parse public_blob");

    use tss_esapi::structures::Public;
    use tss_esapi::traits::UnMarshall;
    let tpm_public = Public::unmarshall(&public_blob).expect("unmarshall public");

    match &tpm_public {
        Public::Ecc { unique, .. } => {
            let tpm_x = unique.x().value();
            let tpm_y = unique.y().value();

            let mut tpm_x_padded = vec![0u8; 32];
            let x_start = 32 - tpm_x.len();
            tpm_x_padded[x_start..].copy_from_slice(tpm_x);

            let mut tpm_y_padded = vec![0u8; 32];
            let y_start = 32 - tpm_y.len();
            tpm_y_padded[y_start..].copy_from_slice(tpm_y);

            assert_eq!(
                tpm_x_padded, expected_x,
                "TPM public X must match recomputed X"
            );
            assert_eq!(
                tpm_y_padded, expected_y,
                "TPM public Y must match recomputed Y"
            );
        }
        _ => panic!("Expected ECC public"),
    }

    let message = b"test import message";
    let signature = provider
        .sign(&imported.key, -7, message)
        .expect("sign with imported key");

    assert!(!signature.is_empty());
    assert_eq!(signature[0], 0x30);

    use p256::PublicKey;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    let public_key =
        PublicKey::from_sec1_bytes(&imported.cose_public_key).expect("valid public key");
    let verifying_key = VerifyingKey::from(&public_key);
    let sig = Signature::from_der(&signature).expect("parse DER signature");
    verifying_key
        .verify(message, &sig)
        .expect("verify signature with imported key");

    let matches = passless_rs::storage::tpm::portable::provider::verify_public_key_matches(
        &test_scalar,
        &imported.cose_public_key,
    )
    .expect("verify public key match");
    assert!(matches, "recomputed public must match stored COSE key");
}
