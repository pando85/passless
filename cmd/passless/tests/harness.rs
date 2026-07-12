//! E2E Test Harness
//!
//! This module provides infrastructure for running E2E tests with the passless authenticator.
//! It handles:
//! - Starting and stopping the authenticator process
//! - Setting up backend-specific prerequisites (password-store, swtpm)
//! - Managing temporary directories and cleanup
//! - Waiting for the authenticator to be ready

use soft_fido2::TransportList;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

/// Backend-specific setup and configuration
#[allow(dead_code)]
pub trait BackendSetup: Send {
    /// Set up the backend and return environment variables for the authenticator
    fn setup(&mut self) -> Result<HashMap<String, String>, Box<dyn std::error::Error>>;

    /// Return command-line arguments for the authenticator
    fn args(&self) -> Vec<String>;

    fn set_device_ids(&mut self, _vendor_id: u16, _product_id: u16) {}

    /// Clean up any resources (called on drop)
    fn cleanup(&mut self) {}
}

/// Local filesystem backend setup
pub struct LocalBackend {
    temp_dir: TempDir,
    vendor_id: Option<u16>,
    product_id: Option<u16>,
    pin_enforcement: Option<String>,
    always_uv: Option<bool>,
    custom_path: Option<std::path::PathBuf>,
}

impl LocalBackend {
    #[allow(dead_code)]
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        Ok(Self {
            temp_dir,
            vendor_id: None,
            product_id: None,
            pin_enforcement: None,
            always_uv: None,
            custom_path: None,
        })
    }

    #[allow(dead_code)]
    pub fn with_pin_enforcement(mut self, enforcement: &str) -> Self {
        self.pin_enforcement = Some(enforcement.to_string());
        self
    }

    #[allow(dead_code)]
    pub fn with_always_uv(mut self, always_uv: bool) -> Self {
        self.always_uv = Some(always_uv);
        self
    }

    #[allow(dead_code)]
    pub fn with_path(path: std::path::PathBuf) -> Self {
        Self {
            temp_dir: TempDir::new().unwrap(),
            vendor_id: None,
            product_id: None,
            pin_enforcement: None,
            always_uv: None,
            custom_path: Some(path),
        }
    }
}

impl BackendSetup for LocalBackend {
    fn setup(&mut self) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        let mut env = HashMap::new();
        env.insert("PASSLESS_E2E_AUTO_ACCEPT_UV".to_string(), "1".to_string());

        if let Some(vendor_id) = self.vendor_id {
            env.insert(
                "PASSLESS_TEST_VENDOR_ID".to_string(),
                format!("0x{:04x}", vendor_id),
            );
        }
        if let Some(product_id) = self.product_id {
            env.insert(
                "PASSLESS_TEST_PRODUCT_ID".to_string(),
                format!("0x{:04x}", product_id),
            );
        }
        if let Some(ref enforcement) = self.pin_enforcement {
            env.insert("PASSLESS_PIN_ENFORCEMENT".to_string(), enforcement.clone());
        }
        if let Some(always_uv) = self.always_uv {
            env.insert("PASSLESS_ALWAYS_UV".to_string(), always_uv.to_string());
        }

        Ok(env)
    }

    fn args(&self) -> Vec<String> {
        let path = self
            .custom_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| self.temp_dir.path().display().to_string());

        vec![
            "--backend-type".to_string(),
            "local".to_string(),
            "--local-path".to_string(),
            path,
            "-v".to_string(),
        ]
    }

    fn set_device_ids(&mut self, vendor_id: u16, product_id: u16) {
        self.vendor_id = Some(vendor_id);
        self.product_id = Some(product_id);
    }
}

/// Password-store backend setup
pub struct PassBackend {
    temp_dir: TempDir,
    gpg_home: PathBuf,
    vendor_id: Option<u16>,
    product_id: Option<u16>,
}

impl PassBackend {
    #[allow(dead_code)]
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let gpg_home = temp_dir.path().join(".gnupg");

        Ok(Self {
            temp_dir,
            gpg_home,
            vendor_id: None,
            product_id: None,
        })
    }

    /// Initialize GPG key for testing
    fn init_gpg(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create batch file for GPG key generation
        let batch_file = self.temp_dir.path().join("gpg-batch");
        std::fs::write(
            &batch_file,
            r#"
Key-Type: RSA
Key-Length: 2048
Name-Real: Passless E2E Test
Name-Email: passless-e2e@test.local
Expire-Date: 0
%no-protection
%commit
"#,
        )?;

        // Generate GPG key
        let output = Command::new("gpg")
            .arg("--homedir")
            .arg(&self.gpg_home)
            .arg("--batch")
            .arg("--gen-key")
            .arg(&batch_file)
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Failed to generate GPG key: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }

        Ok(())
    }

    /// Initialize password store
    fn init_pass(&self) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new("pass")
            .env("PASSWORD_STORE_DIR", self.temp_dir.path())
            .env("GNUPGHOME", &self.gpg_home)
            .arg("init")
            .arg("passless-e2e@test.local")
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Failed to initialize password store: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }

        Ok(())
    }
}

impl BackendSetup for PassBackend {
    fn setup(&mut self) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        println!("🔧 Setting up password-store backend...");

        std::fs::create_dir_all(&self.gpg_home)?;
        std::fs::create_dir_all(self.temp_dir.path().join("fido2"))?;

        // Set restrictive permissions on GPG home
        #[cfg(unix)]
        {
            std::fs::set_permissions(&self.gpg_home, std::fs::Permissions::from_mode(0o700))?;
        }

        self.init_gpg()?;
        println!("   ✓ GPG key generated");

        self.init_pass()?;
        println!("   ✓ Password store initialized");

        let mut env = HashMap::new();
        env.insert("GNUPGHOME".to_string(), self.gpg_home.display().to_string());
        env.insert("PASSLESS_E2E_AUTO_ACCEPT_UV".to_string(), "1".to_string());

        if let Some(vendor_id) = self.vendor_id {
            env.insert(
                "PASSLESS_TEST_VENDOR_ID".to_string(),
                format!("0x{:04x}", vendor_id),
            );
        }
        if let Some(product_id) = self.product_id {
            env.insert(
                "PASSLESS_TEST_PRODUCT_ID".to_string(),
                format!("0x{:04x}", product_id),
            );
        }

        Ok(env)
    }

    fn args(&self) -> Vec<String> {
        vec![
            "--backend-type".to_string(),
            "pass".to_string(),
            "--pass-store-path".to_string(),
            self.temp_dir.path().display().to_string(),
            "--pass-path".to_string(),
            "fido2".to_string(),
            "-v".to_string(),
        ]
    }

    fn set_device_ids(&mut self, vendor_id: u16, product_id: u16) {
        self.vendor_id = Some(vendor_id);
        self.product_id = Some(product_id);
    }
}

/// TPM backend setup (using swtpm)
pub struct TpmBackend {
    temp_dir: TempDir,
    swtpm_process: Option<Child>,
    vendor_id: Option<u16>,
    product_id: Option<u16>,
}

impl TpmBackend {
    #[allow(dead_code)]
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;

        Ok(Self {
            temp_dir,
            swtpm_process: None,
            vendor_id: None,
            product_id: None,
        })
    }

    /// Start swtpm process
    fn start_swtpm(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Start swtpm socket server
        let child = Command::new("swtpm")
            .arg("socket")
            .arg("--tpm2")
            .arg("--tpmstate")
            .arg(format!("dir={}", self.temp_dir.path().display()))
            .arg("--server")
            .arg("type=tcp,port=2321")
            .arg("--ctrl")
            .arg("type=tcp,port=2322")
            .arg("--flags")
            .arg("not-need-init,startup-clear")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        self.swtpm_process = Some(child);

        // Wait for socket to be created
        let start = std::time::Instant::now();
        // Wait for TCP port 2321 to be open on 127.0.0.1
        while std::net::TcpStream::connect("127.0.0.1:2321").is_err() {
            // Check if the process is still alive
            if let Some(ref mut process) = self.swtpm_process
                && let Ok(Some(status)) = process.try_wait()
            {
                return Err(format!("swtpm exited early with status: {}", status).into());
            }

            if start.elapsed() > Duration::from_secs(5) {
                return Err("Timeout waiting for swtpm socket".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(())
    }
}

impl BackendSetup for TpmBackend {
    fn setup(&mut self) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        println!("🔧 Setting up TPM backend (swtpm)...");

        self.start_swtpm()?;
        println!("   ✓ swtpm started");

        std::fs::create_dir_all(self.temp_dir.path().join("credentials"))?;
        let mut env = HashMap::new();
        env.insert(
            "PASSLESS_TPM_TCTI".to_string(),
            "swtpm:host=localhost,port=2321".to_string(),
        );
        env.insert("PASSLESS_E2E_AUTO_ACCEPT_UV".to_string(), "1".to_string());

        if let Some(vendor_id) = self.vendor_id {
            env.insert(
                "PASSLESS_TEST_VENDOR_ID".to_string(),
                format!("0x{:04x}", vendor_id),
            );
        }
        if let Some(product_id) = self.product_id {
            env.insert(
                "PASSLESS_TEST_PRODUCT_ID".to_string(),
                format!("0x{:04x}", product_id),
            );
        }

        Ok(env)
    }

    fn args(&self) -> Vec<String> {
        vec![
            "--backend-type".to_string(),
            "tpm".to_string(),
            "--tpm-tcti".to_string(),
            "swtpm:host=localhost,port=2321".to_string(),
            "--tpm-path".to_string(),
            self.temp_dir
                .path()
                .join("credentials")
                .display()
                .to_string(),
            "-v".to_string(),
        ]
    }

    fn set_device_ids(&mut self, vendor_id: u16, product_id: u16) {
        self.vendor_id = Some(vendor_id);
        self.product_id = Some(product_id);
    }

    fn cleanup(&mut self) {
        if let Some(mut process) = self.swtpm_process.take() {
            let _ = process.kill();
            let _ = process.wait();
            println!("   ✓ swtpm stopped");
        }
    }
}

impl Drop for TpmBackend {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Harness for managing the authenticator process
pub struct AuthenticatorHarness {
    process: Option<Child>,
    backend: Box<dyn BackendSetup>,
    started_by_harness: bool,
}

impl AuthenticatorHarness {
    /// Create a new harness with the specified backend
    pub fn new(backend: Box<dyn BackendSetup>) -> Self {
        Self {
            process: None,
            backend,
            started_by_harness: false,
        }
    }

    /// Create a harness with local backend
    #[allow(dead_code)]
    pub fn with_local() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::new(Box::new(LocalBackend::new()?)))
    }

    /// Create a harness with local backend at a specific path (for persistence testing)
    #[allow(dead_code)]
    pub fn with_local_path(path: std::path::PathBuf) -> Self {
        Self::new(Box::new(LocalBackend::with_path(path)))
    }

    /// Create a harness with password-store backend
    #[allow(dead_code)]
    pub fn with_pass() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::new(Box::new(PassBackend::new()?)))
    }

    /// Create a harness with TPM backend
    #[allow(dead_code)]
    pub fn with_tpm() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::new(Box::new(TpmBackend::new()?)))
    }

    #[allow(dead_code)]
    pub fn set_device_ids(&mut self, vendor_id: u16, product_id: u16) {
        self.backend.set_device_ids(vendor_id, product_id);
    }

    /// Wait for a specific number of devices to be available
    fn wait_for_device_count(
        &self,
        expected_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(10);

        while start.elapsed() < timeout {
            if let Ok(list) = TransportList::enumerate()
                && list.len() >= expected_count
            {
                println!("   ✓ Authenticator is ready");
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        Err(format!(
            "Timeout waiting for {} device(s) to be ready",
            expected_count
        )
        .into())
    }

    /// Start the authenticator
    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.start_and_wait_for_device_count(1)
    }

    /// Start the authenticator and wait for a specific number of total devices
    pub fn start_and_wait_for_device_count(
        &mut self,
        expected_device_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting passless authenticator...");

        // Set up backend
        let env_vars = self.backend.setup()?;
        let args = self.backend.args();

        // Build the cargo command
        let mut cmd = Command::new("cargo");
        cmd.arg("run")
            .arg("--")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Add environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        // Spawn the process
        let mut child = cmd.spawn()?;

        // Spawn threads to capture stdout/stderr using a small helper
        fn spawn_log_thread<R: Read + Send + 'static>(r: R) {
            thread::spawn(move || {
                let reader = BufReader::new(r);
                for line in reader.lines().map_while(Result::ok) {
                    println!("{}", line);
                }
            });
        }

        if let Some(stdout) = child.stdout.take() {
            spawn_log_thread(stdout);
        }

        if let Some(stderr) = child.stderr.take() {
            spawn_log_thread(stderr);
        }

        self.process = Some(child);
        self.started_by_harness = true;

        println!("   ✓ Authenticator process started");
        println!("Waiting for authenticator to initialize...");

        // Wait for it to be ready
        self.wait_for_device_count(expected_device_count)?;

        Ok(())
    }

    /// Stop the authenticator (if we started it)
    pub fn stop(&mut self) {
        if self.started_by_harness
            && let Some(mut process) = self.process.take()
        {
            println!("Stopping passless authenticator...");
            let _ = process.kill();
            let _ = process.wait();
            println!("   ✓ Authenticator stopped");
        }

        self.backend.cleanup();
    }
}

impl Drop for AuthenticatorHarness {
    fn drop(&mut self) {
        self.stop();
    }
}
