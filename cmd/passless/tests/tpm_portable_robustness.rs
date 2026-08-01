//! Phase 5 robustness tests for TPM portable backend.
//!
//! 5.2 — Concurrency: concurrent create/sign through shared provider
//! 5.3 — Transient-handle leak: handle count must not grow unbounded
//! 5.4 — Power-loss / restart safety: atomic-write semantics

#![cfg(feature = "tpm")]

use passless_rs::storage::TpmStorageAdapter;
use passless_rs::storage::tpm::portable::{PortableParent, TpmCredentialKeyProvider};
use passless_rs::util::atomic_write_in_dir;
use soft_fido2_ctap::key_provider::CredentialKeyProvider;

use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
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

fn verify_signature(cose_pub: &[u8], message: &[u8], der_sig: &[u8]) {
    use p256::PublicKey;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    let pk = PublicKey::from_sec1_bytes(cose_pub).expect("parse public key");
    let vk = VerifyingKey::from(&pk);
    let sig = Signature::from_der(der_sig).expect("parse DER signature");
    vk.verify(message, &sig).expect("signature must verify");
}

fn count_transient_handles(tcti: &str) -> usize {
    use tss_esapi::constants::{CapabilityType, tss::TPM2_TRANSIENT_FIRST};
    use tss_esapi::structures::CapabilityData;

    let tcti_conf = std::str::FromStr::from_str(tcti).expect("parse tcti");
    let mut ctx = tss_esapi::Context::new(tcti_conf).expect("create context");

    let mut total = 0usize;
    let mut property = TPM2_TRANSIENT_FIRST;
    loop {
        let (cap_data, more) = ctx
            .get_capability(CapabilityType::Handles, property, 256)
            .expect("get_capability transient handles");
        match cap_data {
            CapabilityData::Handles(list) => {
                let count = list.len();
                total += count;
                if !more || count == 0 {
                    break;
                }
                if let Some(last) = list.last() {
                    property = u32::from(*last) + 1;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    total
}

#[test]
fn test_5_2_concurrent_create_and_sign() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24912, 24911));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");
    let seed = [0x42u8; 32];
    parent.provision(&seed).expect("provision");

    let provider = Arc::new(
        TpmCredentialKeyProvider::new(storage_dir.clone(), Some(swtpm.tcti()))
            .expect("create provider"),
    );

    let num_threads = 4usize;
    let ops_per_thread = 5usize;
    let barrier = Arc::new(std::sync::Barrier::new(num_threads));

    type ThreadResult = Result<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>, String>;
    let mut handles = Vec::new();
    let results: Arc<Mutex<Vec<ThreadResult>>> =
        Arc::new(Mutex::new(Vec::with_capacity(num_threads)));

    for t in 0..num_threads {
        let provider = Arc::clone(&provider);
        let barrier = Arc::clone(&barrier);
        let results = Arc::clone(&results);

        let h = std::thread::Builder::new()
            .name(format!("concurrent-{t}"))
            .spawn(move || {
                let mut local_results = Vec::new();
                barrier.wait();

                for i in 0..ops_per_thread {
                    let generated = provider.generate(-7).map_err(|e| format!("gen: {e:?}"))?;

                    let message = format!("thread-{t}-op-{i}-payload").into_bytes();
                    let sig = provider
                        .sign(&generated.key, -7, &message)
                        .map_err(|e| format!("sign: {e:?}"))?;

                    local_results.push((generated.cose_public_key, message, sig));
                }

                results.lock().unwrap().push(Ok(local_results));
                Ok::<(), String>(())
            })
            .expect("spawn thread");
        handles.push(h);
    }

    for h in handles {
        h.join()
            .expect("thread panicked")
            .expect("thread returned err");
    }

    let all = results.lock().unwrap();
    assert_eq!(all.len(), num_threads);

    let mut total_ops = 0usize;
    for thread_result in all.iter() {
        let entries = thread_result.as_ref().expect("thread result ok");
        for (cose, msg, sig) in entries {
            verify_signature(cose, msg, sig);
            total_ops += 1;
        }
    }
    assert_eq!(total_ops, num_threads * ops_per_thread);
}

#[test]
fn test_5_3_transient_handle_leak() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24922, 24921));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");
    let seed = [0x42u8; 32];
    parent.provision(&seed).expect("provision");

    let provider = TpmCredentialKeyProvider::new(storage_dir.clone(), Some(swtpm.tcti()))
        .expect("create provider");

    let baseline = count_transient_handles(&swtpm.tcti());

    let iterations = 30usize;
    for i in 0..iterations {
        let generated = provider.generate(-7).expect("generate key");
        let message = format!("leak-test-{i}").into_bytes();
        let sig = provider.sign(&generated.key, -7, &message).expect("sign");
        verify_signature(&generated.cose_public_key, &message, &sig);
    }

    let after = count_transient_handles(&swtpm.tcti());

    assert!(
        after <= baseline + 2,
        "transient handles leaked: baseline={baseline}, after={after} (delta={})",
        after.saturating_sub(baseline)
    );
}

#[test]
fn test_5_4_atomic_write_power_loss_safety() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().expect("create temp dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("set secure permissions");
    }

    let filename = "cred.tpm";
    let original_data = b"original-credential-payload-1234567890";

    atomic_write_in_dir(dir.path(), filename, original_data).expect("initial write");

    let contents = std::fs::read(dir.path().join(filename)).expect("read back");
    assert_eq!(contents, original_data);

    let tmp_pattern = format!(".tmp.{}.", std::process::id());
    let leftover_temps: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with(&tmp_pattern))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        leftover_temps.is_empty(),
        "successful atomic write must not leave temp files behind"
    );

    let overwrite_data = b"new-data-overwrite-complete";
    atomic_write_in_dir(dir.path(), filename, overwrite_data).expect("overwrite");

    let overwritten = std::fs::read(dir.path().join(filename)).expect("read after overwrite");
    assert_eq!(overwritten, overwrite_data);

    let leftover_temps_after: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read dir after overwrite")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with(&tmp_pattern))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        leftover_temps_after.is_empty(),
        "overwrite must not leave temp files behind"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
            .expect("make dir read-only");

        let result = atomic_write_in_dir(dir.path(), filename, b"should-fail");
        assert!(result.is_err(), "write to read-only dir must fail");

        let still_intact =
            std::fs::read(dir.path().join(filename)).expect("read after failed write");
        assert_eq!(
            still_intact, overwrite_data,
            "failed write must not corrupt existing file"
        );

        let leftover_temps_bad: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir after failed write")
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with(&tmp_pattern))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            leftover_temps_bad.is_empty(),
            "failed write must not leave temp files behind"
        );

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore dir permissions");
    }
}

#[test]
fn test_5_4_portable_credential_survives_failed_overwrite() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24932, 24931));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");
    let seed = [0x42u8; 32];
    parent.provision(&seed).expect("provision");

    let mut adapter =
        TpmStorageAdapter::new_portable(storage_dir.clone(), Some(swtpm.tcti()), true)
            .expect("create portable adapter");

    let provider = TpmCredentialKeyProvider::new(storage_dir.clone(), Some(swtpm.tcti()))
        .expect("create provider for signing");

    let generated = provider.generate(-7).expect("generate TPM key");

    let cred = soft_fido2::Credential {
        id: vec![0xAA, 0xBB, 0xCC, 0xDD],
        rp: soft_fido2_ctap::types::RelyingParty {
            id: "example.com".to_string(),
            name: Some("Example".to_string()),
        },
        user: soft_fido2_ctap::types::User {
            id: vec![1, 2, 3, 4],
            name: Some("testuser".to_string()),
            display_name: Some("Test User".to_string()),
        },
        sign_count: 0,
        alg: -7,
        key: generated.key,
        created: 1234567890,
        discoverable: true,
        extensions: soft_fido2::Extensions {
            cred_protect: Some(1),
            hmac_secret: None,
            cred_random: None,
        },
        backup_state: soft_fido2::CredentialBackupState::NotEligible,
    };

    adapter.write_credential(&cred).expect("write credential");

    let message = b"pre-failure-signature-test";
    let sig_before = provider
        .sign(&cred.key, -7, message)
        .expect("sign before overwrite attempt");
    verify_signature(&generated.cose_public_key, message, &sig_before);

    let rp_dir = storage_dir.join("example.com");
    let cred_files: Vec<_> = std::fs::read_dir(&rp_dir)
        .expect("read rp dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "tpm")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(cred_files.len(), 1, "expected exactly one credential file");
    let cred_path = cred_files[0].path();
    let original_bytes = std::fs::read(&cred_path).expect("read original cred file");
    assert!(
        !original_bytes.is_empty(),
        "stored credential must not be empty"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&rp_dir, std::fs::Permissions::from_mode(0o500))
            .expect("make rp dir read-only");

        let mut adapter2 =
            TpmStorageAdapter::new_portable(storage_dir.clone(), Some(swtpm.tcti()), true)
                .expect("create adapter for failed overwrite");
        let overwrite_result = adapter2.write_credential(&cred);
        assert!(
            overwrite_result.is_err(),
            "overwrite to read-only dir must fail"
        );

        let after_bytes = std::fs::read(&cred_path).expect("read credential after failed write");
        assert_eq!(
            after_bytes, original_bytes,
            "credential file must be unchanged after failed overwrite"
        );

        std::fs::set_permissions(&rp_dir, std::fs::Permissions::from_mode(0o700))
            .expect("restore rp dir permissions");
    }

    let adapter3 = TpmStorageAdapter::new_portable(storage_dir.clone(), Some(swtpm.tcti()), true)
        .expect("create adapter for reload");
    let reloaded = adapter3
        .read_credential_from_path_no_cache(&cred_path)
        .expect("reload credential after failed overwrite");

    assert_eq!(reloaded.id, cred.id);
    assert_eq!(reloaded.rp.id, cred.rp.id);

    let sig_after = provider
        .sign(&reloaded.key, -7, message)
        .expect("sign after reload");
    verify_signature(&generated.cose_public_key, message, &sig_after);
}
