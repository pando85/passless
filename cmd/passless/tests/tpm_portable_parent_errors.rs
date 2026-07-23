//! Integration tests for TPM portable parent error handling (Phase 3.2 + 3.3).

#![cfg(feature = "tpm")]

use passless_rs::storage::tpm::portable::PortableParent;
use passless_rs::storage::tpm::portable::parent::{
    build_parent_public, compute_name, derive_parent_material,
};

use std::process::{Child, Command};
use std::time::Duration;

use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::resource_handles::Provision;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, PublicBuilder,
    PublicEccParametersBuilder, SymmetricDefinitionObject,
};
use tss_esapi::traits::Marshall;

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

fn create_foreign_persistent(context: &mut Context, handle_value: u32) {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .expect("build object attributes");

    let ecc_params = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .expect("build ECC parameters");

    let foreign_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .expect("build foreign public");

    let primary = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, foreign_pub, None, None, None, None)
        })
        .expect("create foreign primary");

    let persistent_tpm_handle =
        tss_esapi::handles::PersistentTpmHandle::new(handle_value).expect("create handle");
    let persistent = Persistent::from(persistent_tpm_handle);

    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(Provision::Owner, primary.key_handle.into(), persistent)
        })
        .expect("persist foreign object");
}

#[test]
fn test_collision_foreign_object_at_persistent_handle() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24512, 24511));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();

    let tcti_str = swtpm.tcti();
    let tcti_conf: tss_esapi::Tcti = std::str::FromStr::from_str(&tcti_str).expect("parse tcti");
    let mut context = Context::new(tcti_conf).expect("create context");

    create_foreign_persistent(&mut context, 0x81000001);

    let foreign_tpm_handle =
        tss_esapi::handles::PersistentTpmHandle::new(0x81000001).expect("create handle");
    let foreign_esys_handle = context
        .tr_from_tpm_public(foreign_tpm_handle.into())
        .expect("read foreign handle before provision");
    let foreign_key_handle = tss_esapi::handles::KeyHandle::from(foreign_esys_handle);
    let (foreign_public_before, _, _) = context
        .read_public(foreign_key_handle)
        .expect("read foreign public before");

    drop(context);

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");

    let seed = [0x42u8; 32];
    let result = parent.provision(&seed);

    assert!(
        result.is_err(),
        "provision should refuse when foreign object occupies handle"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err,
        soft_fido2::Error::DoesAlreadyExist,
        "expected DoesAlreadyExist, got {:?}",
        err
    );
    assert_ne!(
        err,
        soft_fido2::Error::Other,
        "must not be generic Error::Other"
    );

    let tcti_conf2: tss_esapi::Tcti =
        std::str::FromStr::from_str(&swtpm.tcti()).expect("parse tcti");
    let mut context2 = Context::new(tcti_conf2).expect("create context2");

    let check_handle =
        tss_esapi::handles::PersistentTpmHandle::new(0x81000001).expect("create handle for check");
    let check_esys = context2
        .tr_from_tpm_public(check_handle.into())
        .expect("foreign handle should still exist");
    let check_key = tss_esapi::handles::KeyHandle::from(check_esys);
    let (foreign_public_after, _, _) = context2
        .read_public(check_key)
        .expect("read foreign public after");

    assert_eq!(
        foreign_public_before, foreign_public_after,
        "foreign object must not have been evicted"
    );
}

#[test]
fn test_missing_parent_metadata() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24522, 24521));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");

    assert!(!parent.is_provisioned());

    let result = parent.load_metadata();
    assert!(result.is_err(), "load_metadata should fail on empty dir");
    let err = match result {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(
        err,
        soft_fido2::Error::InitializationFailed,
        "expected InitializationFailed, got {:?}",
        err
    );
    assert_ne!(
        err,
        soft_fido2::Error::Other,
        "must not be generic Error::Other"
    );
}

#[test]
fn test_wrong_parent_mismatch() {
    let _ = env_logger::builder().is_test(true).try_init();

    let swtpm = SwtpmInstance::new((24532, 24531));
    let dir = tempfile::tempdir().expect("create temp dir");
    let storage_dir = dir.path().to_path_buf();

    let parent =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent");

    let seed_a = [0x42u8; 32];
    parent.provision(&seed_a).expect("provision with seed A");

    let seed_b = [0x99u8; 32];
    let material_b = derive_parent_material(&seed_b).expect("derive material B");
    let foreign_public =
        build_parent_public(&material_b.pub_x, &material_b.pub_y).expect("build public B");
    let foreign_tpmt = foreign_public.marshall().expect("marshall public B");
    let foreign_name = compute_name(&foreign_tpmt);

    let tampered_metadata = serde_json::json!({
        "version": 1,
        "public_blob": foreign_tpmt,
        "parent_name": foreign_name,
        "persistent_handle": 0x81000001u32,
    });

    let metadata_path = storage_dir.join("portable_parent.json");
    let tampered_bytes = serde_json::to_vec(&tampered_metadata).expect("serialize tampered");
    std::fs::write(&metadata_path, &tampered_bytes).expect("write tampered metadata");

    let parent2 =
        PortableParent::new(storage_dir.clone(), Some(swtpm.tcti())).expect("create parent2");

    let metadata = parent2.load_metadata().expect("load tampered metadata");
    let result = parent2.verify_parent(&metadata);

    assert!(
        result.is_err(),
        "verify_parent should fail with mismatched parent"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err,
        soft_fido2::Error::CtapError(0x3D),
        "expected CtapError(0x3D), got {:?}",
        err
    );
    assert_ne!(
        err,
        soft_fido2::Error::Other,
        "must not be generic Error::Other"
    );
}
