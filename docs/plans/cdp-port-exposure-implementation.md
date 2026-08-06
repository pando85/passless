# Implementation Plan: ADR 0004 — CDP Port Exposure

## Status of current changes

- [x] `CdpExposeMode` enum (config.rs)
- [x] `browser_cdp_expose` + `browser_cdp_port` fields on `AgentProfileConfig`
- [x] Config validation: relaxed `browser_user` constraint in port mode
- [x] Runtime validation: relaxed uid checks in port mode, default to principal user
- [x] `BrowserConfig` struct: added `cdp_expose` + `cdp_port` fields
- [x] Compiles clean

## Remaining work

### Step 1: Populate `BrowserConfig` from profile config (runtime.rs)

**File:** `cmd/passless/src/agent/runtime.rs` ~line 3624
**What:** The `BrowserConfig` construction site needs to pass through the new fields.

```rust
cdp_expose: config.browser_cdp_expose.unwrap_or_default(),
cdp_port: config.browser_cdp_port.unwrap_or(0),
```

**Verify:** `cargo check`

---

### Step 2: Conditional browser launch — port mode (browser.rs)

**File:** `cmd/passless/src/agent/browser.rs`

#### 2a. `build_browser_command` (~line 1531)

Replace hardcoded `--remote-debugging-pipe` with:

```rust
match config.cdp_expose {
    CdpExposeMode::Pipe => { cmd.arg("--remote-debugging-pipe"); }
    CdpExposeMode::Port => {
        cmd.arg(format!("--remote-debugging-port={}", config.cdp_port));
        // Explicitly bind localhost only
        cmd.arg("--remote-debugging-address=127.0.0.1");
    }
}
```

#### 2b. `launch_pending` (~line 593)

In port mode, skip `create_cdp_pipes()` and `spawn_browser_hardened()`. Use a
simpler spawn path (no pipe fd remapping):

```rust
let (child, cdp_endpoints) = match config.cdp_expose {
    CdpExposeMode::Pipe => {
        let cdp = create_cdp_pipes()?;
        let child = self.spawner.spawn_browser(config, &profile_dir, &cdp)?;
        let endpoints = DaemonCdpEndpoints { ... };
        // consume pipe fds
        (child, Some(endpoints))
    }
    CdpExposeMode::Port => {
        let child = spawn_browser_port_mode(config, &profile_dir)?;
        (child, None)
    }
};
```

#### 2c. New function: `spawn_browser_port_mode`

Simpler spawn without pipe fd dup2. Still applies hardening (setsid,
close_range, RLIMIT_NOFILE, PR_SET_NO_NEW_PRIVS, uid/gid drop) but with
an empty preserve-fds list:

```rust
fn spawn_browser_port_mode(config: &BrowserConfig, profile_dir: &Path) -> Result<Child, LaunchError> {
    let setup = config.hardening();
    setup.validate()?;
    let mut cmd = build_browser_command(config, profile_dir);
    unsafe {
        cmd.pre_exec(move || {
            setup.apply(&[])  // no fds to preserve
        });
    }
    cmd.spawn()
}
```

#### 2d. `BrowserLease` — make `cdp` field `Option`

The `cdp: Option<DaemonCdpEndpoints>` field already exists as `Option` (check).
In port mode it's `None`.

**Verify:** `cargo check`

---

### Step 3: DevToolsActivePort discovery (browser.rs)

**File:** `cmd/passless/src/agent/browser.rs`

After spawning in port mode, poll for Chromium's `DevToolsActivePort` file:

```rust
fn discover_cdp_endpoint(profile_dir: &Path, timeout: Duration) -> Result<String, LaunchError> {
    let port_file = profile_dir.join("DevToolsActivePort");
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(content) = fs::read_to_string(&port_file) {
            let lines: Vec<&str> = content.lines().collect();
            if lines.len() >= 2 {
                let port = lines[0].trim();
                let ws_path = lines[1].trim();
                return Ok(format!("ws://127.0.0.1:{}{}", port, ws_path));
            }
        }
        if Instant::now() >= deadline {
            return Err(LaunchError::CdpDiscoveryTimeout);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
```

`DevToolsActivePort` format (Chromium):
```
9222
/devtools/browser/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**Verify:** Unit test with a mock file.

---

### Step 4: Write `cdp-endpoint` file (browser.rs)

After discovery, write the WebSocket URL to `<runtime_dir>/cdp-endpoint`:

```rust
fn write_cdp_endpoint(runtime_dir: &Path, url: &str, uid: u32, gid: u32) -> Result<(), LaunchError> {
    let path = runtime_dir.join("cdp-endpoint");
    fs::write(&path, url)?;
    // mode 0600, owned by principal user
    chown(&path, uid, gid)?;
    set_permissions(&path, 0o600)?;
    Ok(())
}
```

**Verify:** Check file exists with correct perms in integration test.

---

### Step 5: Store CDP endpoint in lease + expose via `browser-status`

#### 5a. Add field to `BrowserLease` (browser.rs)

```rust
pub cdp_endpoint: Option<String>,  // ws:// URL in port mode
```

#### 5b. Update `BrowserStatusResponse` (protocol.rs ~line 725)

```rust
pub struct BrowserStatusResponse {
    pub running: bool,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdp_endpoint: Option<String>,
}
```

#### 5c. Populate in `handle_browser_status` (runtime.rs ~line 3840)

Read `cdp_endpoint` from the lease snapshot and include in response.

**Verify:** `cargo check` + test `browser-status` output.

---

### Step 6: Block `browser-control` in port mode (runtime.rs)

In `handle_browser_control` (~line 3876), if the lease has no CDP pipes
(port mode), return an error:

```rust
if lease.cdp.is_none() {
    return Err(ProtocolError::new(
        ErrorCode::BrowserNotAvailable,
        format!(
            "browser-control is unavailable in port mode; connect directly via CDP: {}",
            lease.cdp_endpoint.as_deref().unwrap_or("<endpoint not yet discovered>")
        ),
    ));
}
```

**Verify:** Test that `browser-control` returns the error with the endpoint URL.

---

### Step 7: Audit event for exposure mode

In the lease creation audit event, include the exposure mode:

```rust
audit.record(AuditEvent::BrowserLaunched {
    lease_id,
    profile_id,
    cdp_expose: config.cdp_expose.to_string(),
    ...
});
```

**Verify:** Check audit log contains the field.

---

### Step 8: Validation — reject `--remote-debugging-address` in extra_args

In config validation or `build_browser_command`, reject if `extra_args`
contains `--remote-debugging-address` (prevent override of localhost binding):

```rust
if config.extra_args.iter().any(|a| a.starts_with("--remote-debugging-address")) {
    return Err(LaunchError::InvalidArg(
        "--remote-debugging-address is not allowed (localhost binding enforced)".into()
    ));
}
```

Also reject `--remote-debugging-pipe` and `--remote-debugging-port` in
extra_args (prevent conflicts):

```rust
if config.extra_args.iter().any(|a|
    a.starts_with("--remote-debugging-pipe") || a.starts_with("--remote-debugging-port")
) {
    return Err(LaunchError::InvalidArg(
        "remote debugging flags are managed by passless; remove from browser_command".into()
    ));
}
```

**Verify:** Unit test for config rejection.

---

### Step 9: Import `CdpExposeMode` in browser.rs

Add the import:
```rust
use passless_core::agent::config::CdpExposeMode;
```

**Verify:** `cargo check`

---

### Step 10: Tests

1. **Unit test (config.rs):** Port mode allows `browser_user == principal_user`
2. **Unit test (config.rs):** Port mode allows `browser_user` omitted
3. **Unit test (config.rs):** Pipe mode still rejects same user
4. **Unit test (config.rs):** Reject `--remote-debugging-*` in extra_args
5. **Unit test (browser.rs):** `discover_cdp_endpoint` with mock file
6. **Unit test (browser.rs):** `build_browser_command` emits correct flags per mode
7. **Integration test:** Full port-mode launch with a real Chromium (if available in CI)

**Verify:** `cargo test`

---

### Step 11: Update documentation

- `docs/agents/configuration.md`: Add `browser_cdp_expose` and `browser_cdp_port` fields
- `docs/agents/delegated-session.md`: Add trusted mode workflow
- `docs/agents/security.md`: Add port mode threat model section

**Verify:** Review rendered docs.

---

### Step 12: Update passless config for our deployment

Update `~/.config/passless/config.toml` (and dotfiles):

```toml
[agents.profiles.opencode]
mode = "delegated-session"
principal_user = "agil"
browser_cdp_expose = "port"
browser_cdp_port = 9222
browser_command = ["/usr/bin/chromium"]
browser_runtime_root = "/home/agil/.local/share/passless/browser"
start_url = "https://github.com"
credential_refs = [...]
max_grant_ttl = 300
max_session_ttl = 3600
```

No `browser_user` needed (defaults to principal in port mode).

**Verify:** `passless agent-admin profile check opencode`

---

### Step 13: End-to-end test

1. Start passless daemon (as root, system service)
2. `passless agent-admin profile check opencode` → OK
3. `passless agent run --profile opencode -- sleep 3600` (background)
4. Inside session: `passless agent --profile opencode doctor` → healthy
5. `passless agent --profile opencode delegation request --rp github.com --credential <ref> --session-ttl 3600 --reason "test"`
6. Read `cdp-endpoint` file → `ws://127.0.0.1:9222/devtools/browser/<uuid>`
7. Connect Playwright: `connectOverCDP("ws://127.0.0.1:9222/devtools/browser/<uuid>")`
8. Navigate, snapshot, verify authenticated session
9. Revoke delegation → browser killed

**Verify:** All steps pass.

---

## Execution order

Steps 1→9 are code changes (sequential, each verified with `cargo check`).
Step 10 is tests (after all code compiles).
Step 11 is docs (parallel with tests).
Step 12-13 are deployment + e2e (after tests pass).

## Risk: `spawn_browser_hardened` signature

The `ChildSpawner` trait has `spawn_browser(&self, config, profile_dir, cdp: &CdpPipes)`.
In port mode we don't have pipes. Options:
- A) Make `cdp` parameter `Option<&CdpPipes>` in the trait
- B) Add a separate `spawn_browser_port` method to the trait
- C) Bypass the trait in port mode (call `spawn_browser_port_mode` directly)

**Recommendation:** Option C — the trait exists for testability of the pipe path.
Port mode is simpler and doesn't need the same mock infrastructure. Add a
`#[cfg(test)]` mock if needed later.
