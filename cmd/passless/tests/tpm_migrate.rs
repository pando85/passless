//! Integration tests for TPM credential migration (legacy → portable).

#![cfg(feature = "tpm")]

use passless_rs::storage::TpmStorageAdapter;
use passless_rs::storage::tpm::migrate::migrate_credentials;
use passless_rs::storage::tpm::portable::{PortableParent, TpmCredentialKeyProvider};

use soft_fido2_ctap::SecBytes;
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

fn make_legacy_cred(cred_id: &[u8], rp_id: &str, scalar: &[u8; 32]) -> soft_fido2::Credential {
    soft_fido2::Credential {
        id: cred_id.to_vec(),
        rp: soft_fido2_ctap::types::RelyingParty {
            id: rp_id.to_string(),
            name: Some(format!("{} RP", rp_id)),
        },
        user: soft_fido2_ctap::types::User {
            id: vec![1, 2, 3, 4],
            name: Some("testuser".to_string()),
            display_name: Some("Test User".to_string()),
        },
        sign_count: 0,
        alg: -7,
        key: soft_fido2_ctap::CredentialKey::software(SecBytes::from_slice(scalar)),
        created: 1234567890,
        discoverable: true,
        backup_state: soft_fido2::CredentialBackupState::NotEligible,
        extensions: soft_fido2::Extensions {
            cred_protect: Some(1),
            hmac_secret: None,
            cred_random: None,
        },
    }
}

fn compute_cose_pub(scalar: &[u8; 32]) -> Vec<u8> {
    let (x, y) = passless_rs::storage::tpm::portable::provider::compute_public_from_scalar(scalar)
        .expect("compute public from scalar");
    let mut cose = vec![0x04];
    cose.extend_from_slice(&x);
    cose.extend_from_slice(&y);
    cose
}

fn write_legacy(
    storage_dir: &std::path::Path,
    tcti: &Option<String>,
    cred: &soft_fido2::Credential,
) {
    let mut adapter =
        TpmStorageAdapter::new_with_options(storage_dir.to_path_buf(), tcti.clone(), true)
            .expect("create legacy adapter");
    adapter
        .write_credential(cred)
        .expect("write legacy credential");
}

fn provision_parent(storage_dir: &std::path::Path, tcti: &Option<String>) {
    let parent =
        PortableParent::new(storage_dir.to_path_buf(), tcti.clone()).expect("create parent");
    let seed = [0x42u8; 32];
    parent.provision(&seed).expect("provision portable parent");
    assert!(parent.is_provisioned());
}

fn verify_sig(cose_pub: &[u8], message: &[u8], signature_der: &[u8]) {
    use p256::PublicKey;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    let public_key = PublicKey::from_sec1_bytes(cose_pub).expect("parse public key");
    let verifying_key = VerifyingKey::from(&public_key);
    let sig = Signature::from_der(signature_der).expect("parse DER signature");
    verifying_key
        .verify(message, &sig)
        .expect("signature must verify against original public key");
}

const TEST_SCALAR_A: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, 0x82, 0x93, 0xA4, 0xB5, 0xC6, 0xD7, 0xE8, 0xF9,
];

const TEST_SCALAR_B: [u8; 32] = [
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01,
];

#[test]
fn test_tpm_migrate_happy_path() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((25512, 25511));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();
    let tcti = Some(swtpm.tcti());

    let orig_cose = compute_cose_pub(&TEST_SCALAR_A);

    let legacy_cred = make_legacy_cred(&[0xAA, 0xBB, 0xCC, 0xDD], "example.com", &TEST_SCALAR_A);

    write_legacy(&storage_dir, &tcti, &legacy_cred);

    let cred_paths = passless_rs::storage::index::load_credential_paths(&storage_dir, "tpm")
        .expect("load credential paths");
    assert_eq!(cred_paths.id.len(), 1);

    let legacy_path = cred_paths.id.values().next().unwrap().to_path(&storage_dir);
    assert!(legacy_path.exists());

    provision_parent(&storage_dir, &tcti);

    let report = migrate_credentials(
        None,
        true,
        false,
        None,
        Some(storage_dir.to_string_lossy().to_string()),
        tcti.clone(),
    )
    .expect("migrate_credentials succeeds");

    assert_eq!(report.migrated.len(), 1);
    assert_eq!(report.already_portable_count(), 0);
    assert_eq!(report.non_es256_skip_count(), 0);
    assert_eq!(report.failed.len(), 0);

    let portable_adapter = TpmStorageAdapter::new_portable(storage_dir.clone(), tcti.clone(), true)
        .expect("create portable adapter");

    let portable_cred = portable_adapter
        .read_credential_from_path_no_cache(&legacy_path)
        .expect("read back portable credential");

    assert_eq!(portable_cred.id, legacy_cred.id);
    assert_eq!(portable_cred.rp.id, "example.com");
    assert_eq!(portable_cred.alg, -7);
    assert!(!portable_cred.key.provider.is_software());

    let provider =
        TpmCredentialKeyProvider::new(storage_dir.clone(), tcti.clone()).expect("create provider");

    let test_message = b"test assertion message";
    let signature = provider
        .sign(&portable_cred.key, -7, test_message)
        .expect("sign with migrated key");

    verify_sig(&orig_cose, test_message, &signature);

    let backup_dir = storage_dir.join(".backup");
    let rel = legacy_path.strip_prefix(&storage_dir).unwrap();
    let backup_file = backup_dir.join(rel);
    assert!(backup_file.exists(), "backup file should exist");
}

#[test]
fn test_tpm_migrate_rp_registration_preserved() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((25522, 25521));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();
    let tcti = Some(swtpm.tcti());

    let orig_cose = compute_cose_pub(&TEST_SCALAR_A);
    let cred_id_bytes = vec![0x11, 0x22, 0x33, 0x44];

    let legacy_cred = make_legacy_cred(&cred_id_bytes, "rp-preserve.test", &TEST_SCALAR_A);
    write_legacy(&storage_dir, &tcti, &legacy_cred);
    provision_parent(&storage_dir, &tcti);

    let report = migrate_credentials(
        None,
        true,
        false,
        None,
        Some(storage_dir.to_string_lossy().to_string()),
        tcti.clone(),
    )
    .expect("migrate");

    assert_eq!(report.migrated.len(), 1);
    assert!(report.failed.is_empty());

    let portable_adapter = TpmStorageAdapter::new_portable(storage_dir.clone(), tcti.clone(), true)
        .expect("create portable adapter");

    let cred_paths = passless_rs::storage::index::load_credential_paths(&storage_dir, "tpm")
        .expect("load paths");
    let cred_path = cred_paths.id.values().next().unwrap().to_path(&storage_dir);

    let portable_cred = portable_adapter
        .read_credential_from_path_no_cache(&cred_path)
        .expect("read portable cred");

    assert_eq!(portable_cred.id, cred_id_bytes);
    assert_eq!(portable_cred.alg, -7);
    assert_eq!(portable_cred.rp.id, "rp-preserve.test");
    assert!(!portable_cred.key.provider.is_software());

    let provider =
        TpmCredentialKeyProvider::new(storage_dir.clone(), tcti.clone()).expect("create provider");

    let assertion_msg = b"assertion-from-rp-preserve-test";
    let sig = provider
        .sign(&portable_cred.key, -7, assertion_msg)
        .expect("sign");

    verify_sig(&orig_cose, assertion_msg, &sig);
}

#[test]
fn test_tpm_migrate_backup_created() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((25532, 25531));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();
    let tcti = Some(swtpm.tcti());

    let legacy_cred = make_legacy_cred(&[0xBB, 0xCC], "backup-test.com", &TEST_SCALAR_A);
    write_legacy(&storage_dir, &tcti, &legacy_cred);

    let cred_paths = passless_rs::storage::index::load_credential_paths(&storage_dir, "tpm")
        .expect("load paths");
    let legacy_path = cred_paths.id.values().next().unwrap().to_path(&storage_dir);
    let legacy_bytes_before = std::fs::read(&legacy_path).expect("read legacy file before");

    provision_parent(&storage_dir, &tcti);

    migrate_credentials(
        None,
        true,
        false,
        None,
        Some(storage_dir.to_string_lossy().to_string()),
        tcti.clone(),
    )
    .expect("migrate");

    let backup_dir = storage_dir.join(".backup");
    let rel = legacy_path.strip_prefix(&storage_dir).unwrap();
    let backup_file = backup_dir.join(rel);
    assert!(backup_file.exists(), "backup file must exist");

    let backup_bytes = std::fs::read(&backup_file).expect("read backup");
    let portable_bytes = std::fs::read(&legacy_path).expect("read portable record");

    assert_eq!(
        backup_bytes, legacy_bytes_before,
        "backup must equal original legacy blob"
    );
    assert_ne!(
        backup_bytes, portable_bytes,
        "backup must differ from portable record"
    );
}

#[test]
fn test_tpm_migrate_portability() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm_a = SwtpmInstance::new((25542, 25541));
    let dir_a = tempfile::tempdir().expect("create temp dir");
    let storage_dir_a = dir_a.path().to_path_buf();
    let tcti_a = Some(swtpm_a.tcti());

    let orig_cose = compute_cose_pub(&TEST_SCALAR_A);
    let cred_id_bytes = vec![0xDD, 0xEE, 0xFF, 0x00];

    let legacy_cred = make_legacy_cred(&cred_id_bytes, "portable-rp.test", &TEST_SCALAR_A);
    write_legacy(&storage_dir_a, &tcti_a, &legacy_cred);

    let parent_a =
        PortableParent::new(storage_dir_a.clone(), tcti_a.clone()).expect("create parent A");
    let seed = [0x42u8; 32];
    parent_a.provision(&seed).expect("provision A");

    migrate_credentials(
        None,
        true,
        false,
        None,
        Some(storage_dir_a.to_string_lossy().to_string()),
        tcti_a.clone(),
    )
    .expect("migrate on A");

    let swtpm_b = SwtpmInstance::new((25553, 25552));
    let dir_b = tempfile::tempdir().expect("create temp dir");
    let storage_dir_b = dir_b.path().to_path_buf();
    let tcti_b = Some(swtpm_b.tcti());

    let parent_b =
        PortableParent::new(storage_dir_b.clone(), tcti_b.clone()).expect("create parent B");
    parent_b.provision(&seed).expect("provision B");

    let cred_paths_a = passless_rs::storage::index::load_credential_paths(&storage_dir_a, "tpm")
        .expect("load paths A");
    let cred_path_a = cred_paths_a
        .id
        .values()
        .next()
        .unwrap()
        .to_path(&storage_dir_a);
    let rel = cred_path_a.strip_prefix(&storage_dir_a).unwrap();

    let dest_path = storage_dir_b.join(rel);
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).expect("create rp dir on B");
    }
    std::fs::copy(&cred_path_a, &dest_path).expect("copy portable record to B");

    let portable_adapter_b =
        TpmStorageAdapter::new_portable(storage_dir_b.clone(), tcti_b.clone(), true)
            .expect("create portable adapter on B");

    let portable_cred_b = portable_adapter_b
        .read_credential_from_path_no_cache(&dest_path)
        .expect("read portable cred on B");

    assert_eq!(portable_cred_b.id, cred_id_bytes);
    assert!(!portable_cred_b.key.provider.is_software());

    let provider_b =
        TpmCredentialKeyProvider::new(storage_dir_b.clone(), tcti_b.clone()).expect("provider B");

    let msg = b"cross-tpm-portability-test";
    let sig_b = provider_b
        .sign(&portable_cred_b.key, -7, msg)
        .expect("sign on B");

    verify_sig(&orig_cose, msg, &sig_b);
}

#[test]
fn test_tpm_migrate_dry_run_purity() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((25562, 25561));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();
    let tcti = Some(swtpm.tcti());

    let legacy_cred = make_legacy_cred(&[0xCC, 0xDD], "dryrun.test", &TEST_SCALAR_A);
    write_legacy(&storage_dir, &tcti, &legacy_cred);

    let cred_paths = passless_rs::storage::index::load_credential_paths(&storage_dir, "tpm")
        .expect("load paths");
    let legacy_path = cred_paths.id.values().next().unwrap().to_path(&storage_dir);
    let legacy_bytes_before = std::fs::read(&legacy_path).expect("read legacy before");

    provision_parent(&storage_dir, &tcti);

    let report = migrate_credentials(
        None,
        true,
        true,
        None,
        Some(storage_dir.to_string_lossy().to_string()),
        tcti.clone(),
    )
    .expect("dry run migrate");

    assert_eq!(
        report.migrated.len(),
        1,
        "dry run should list would-migrate"
    );
    assert!(report.failed.is_empty());

    let legacy_bytes_after = std::fs::read(&legacy_path).expect("read legacy after");
    assert_eq!(
        legacy_bytes_before, legacy_bytes_after,
        "legacy file must be unchanged after dry run"
    );

    let backup_dir = storage_dir.join(".backup");
    assert!(
        !backup_dir.exists(),
        "no .backup directory should be created by dry run"
    );

    let portable_adapter_result =
        TpmStorageAdapter::new_portable(storage_dir.clone(), tcti.clone(), true);
    if let Ok(adapter) = portable_adapter_result {
        let read_result = adapter.read_credential_from_path_no_cache(&legacy_path);
        assert!(
            read_result.is_err(),
            "portable adapter should not be able to read legacy record after dry run"
        );
    }
}

#[test]
fn test_tpm_migrate_idempotency() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((25572, 25571));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();
    let tcti = Some(swtpm.tcti());

    let orig_cose = compute_cose_pub(&TEST_SCALAR_A);

    let legacy_cred = make_legacy_cred(&[0xEE, 0xFF], "idempotent.test", &TEST_SCALAR_A);
    write_legacy(&storage_dir, &tcti, &legacy_cred);
    provision_parent(&storage_dir, &tcti);

    let report1 = migrate_credentials(
        None,
        true,
        false,
        None,
        Some(storage_dir.to_string_lossy().to_string()),
        tcti.clone(),
    )
    .expect("first migrate");

    assert_eq!(report1.migrated.len(), 1);
    assert_eq!(report1.already_portable_count(), 0);

    let report2 = migrate_credentials(
        None,
        true,
        false,
        None,
        Some(storage_dir.to_string_lossy().to_string()),
        tcti.clone(),
    )
    .expect("second migrate");

    assert!(
        report2.migrated.is_empty(),
        "second run should migrate nothing"
    );
    assert!(
        report2.already_portable_count() >= 1,
        "second run should report already-portable"
    );
    assert!(report2.failed.is_empty());

    let portable_adapter = TpmStorageAdapter::new_portable(storage_dir.clone(), tcti.clone(), true)
        .expect("create portable adapter");

    let cred_paths = passless_rs::storage::index::load_credential_paths(&storage_dir, "tpm")
        .expect("load paths");
    let cred_path = cred_paths.id.values().next().unwrap().to_path(&storage_dir);

    let portable_cred = portable_adapter
        .read_credential_from_path_no_cache(&cred_path)
        .expect("read portable cred after idempotent run");

    assert!(!portable_cred.key.provider.is_software());

    let provider =
        TpmCredentialKeyProvider::new(storage_dir.clone(), tcti.clone()).expect("create provider");

    let msg = b"idempotency-verify-msg";
    let sig = provider
        .sign(&portable_cred.key, -7, msg)
        .expect("sign after idempotent run");

    verify_sig(&orig_cose, msg, &sig);
}

#[test]
fn test_tpm_migrate_selection_by_id() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((25582, 25581));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();
    let tcti = Some(swtpm.tcti());

    let cred1_id = vec![0x11, 0x11];
    let cred2_id = vec![0x22, 0x22];

    let cred1 = make_legacy_cred(&cred1_id, "select.com", &TEST_SCALAR_A);
    let cred2 = make_legacy_cred(&cred2_id, "select.com", &TEST_SCALAR_B);

    write_legacy(&storage_dir, &tcti, &cred1);
    write_legacy(&storage_dir, &tcti, &cred2);

    let cred_paths = passless_rs::storage::index::load_credential_paths(&storage_dir, "tpm")
        .expect("load paths");
    assert_eq!(cred_paths.id.len(), 2, "should have two legacy credentials");

    let target_hex = hex::encode(&cred1_id);

    provision_parent(&storage_dir, &tcti);

    let report = migrate_credentials(
        Some(target_hex.clone()),
        false,
        false,
        None,
        Some(storage_dir.to_string_lossy().to_string()),
        tcti.clone(),
    )
    .expect("migrate by id");

    assert_eq!(report.migrated.len(), 1, "only one credential migrated");
    assert!(report.failed.is_empty());

    let legacy_adapter =
        TpmStorageAdapter::new_with_options(storage_dir.clone(), tcti.clone(), true)
            .expect("create legacy adapter");

    let cred2_path = cred_paths.id.get(&cred2_id).unwrap().to_path(&storage_dir);
    let cred2_read = legacy_adapter
        .read_credential_from_path_no_cache(&cred2_path)
        .expect("read cred2 as legacy");
    assert!(
        cred2_read.key.provider.is_software(),
        "cred2 must remain legacy (software key)"
    );

    let portable_adapter = TpmStorageAdapter::new_portable(storage_dir.clone(), tcti.clone(), true)
        .expect("create portable adapter");

    let cred1_path = cred_paths.id.get(&cred1_id).unwrap().to_path(&storage_dir);
    let cred1_read = portable_adapter
        .read_credential_from_path_no_cache(&cred1_path)
        .expect("read cred1 as portable");
    assert!(!cred1_read.key.provider.is_software());
    assert_eq!(cred1_read.id, cred1_id);
}

#[test]
fn test_tpm_migrate_missing_portable_parent() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((25592, 25591));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();
    let tcti = Some(swtpm.tcti());

    let legacy_cred = make_legacy_cred(&[0x33, 0x44], "noparent.test", &TEST_SCALAR_A);
    write_legacy(&storage_dir, &tcti, &legacy_cred);

    let result = migrate_credentials(
        None,
        true,
        false,
        None,
        Some(storage_dir.to_string_lossy().to_string()),
        tcti.clone(),
    );

    assert!(result.is_err(), "migration without parent must fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("provision") || err_msg.contains("passless tpm provision"),
        "error must guide user to provision: got '{}'",
        err_msg
    );
}

#[test]
fn test_tpm_migrate_eddsa_not_migratable() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((25602, 25601));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();
    let tcti = Some(swtpm.tcti());

    let eddsa_scalar = [0x77u8; 32];
    let eddsa_cred = soft_fido2::Credential {
        id: vec![0x55, 0x66],
        rp: soft_fido2_ctap::types::RelyingParty {
            id: "eddsa-test.com".to_string(),
            name: Some("EdDSA Test".to_string()),
        },
        user: soft_fido2_ctap::types::User {
            id: vec![1, 2, 3, 4],
            name: Some("testuser".to_string()),
            display_name: Some("Test User".to_string()),
        },
        sign_count: 0,
        alg: -8,
        key: soft_fido2_ctap::CredentialKey::software(SecBytes::from_slice(&eddsa_scalar)),
        created: 1234567890,
        discoverable: true,
        backup_state: soft_fido2::CredentialBackupState::NotEligible,
        extensions: soft_fido2::Extensions {
            cred_protect: Some(1),
            hmac_secret: None,
            cred_random: None,
        },
    };

    write_legacy(&storage_dir, &tcti, &eddsa_cred);
    provision_parent(&storage_dir, &tcti);

    let report = migrate_credentials(
        None,
        true,
        false,
        None,
        Some(storage_dir.to_string_lossy().to_string()),
        tcti.clone(),
    )
    .expect("migrate with eddsa");

    assert!(
        report.migrated.is_empty(),
        "EdDSA credential must not be migrated"
    );
    assert!(
        report.non_es256_skip_count() >= 1
            || report
                .skipped
                .iter()
                .any(|(_, r)| r.contains("not migratable")),
        "EdDSA must be reported as skipped/not-migratable"
    );

    let legacy_adapter =
        TpmStorageAdapter::new_with_options(storage_dir.clone(), tcti.clone(), true)
            .expect("create legacy adapter");

    let cred_paths = passless_rs::storage::index::load_credential_paths(&storage_dir, "tpm")
        .expect("load paths");
    let eddsa_path = cred_paths
        .id
        .get(&vec![0x55u8, 0x66u8])
        .unwrap()
        .to_path(&storage_dir);
    let eddsa_read = legacy_adapter
        .read_credential_from_path_no_cache(&eddsa_path)
        .expect("read eddsa cred back");
    assert!(
        eddsa_read.key.provider.is_software(),
        "EdDSA credential must remain software (untouched)"
    );
    assert_eq!(eddsa_read.alg, -8);
}
