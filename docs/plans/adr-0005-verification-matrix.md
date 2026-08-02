# ADR 0005 — Full-Implementation Verification Matrix

- **Status:** Verification plan (in progress)
- **Date:** 2026-08-02
- **Covers:** All four rollout phases of [ADR 0005](../decisions/0005-delegated-autonomous-authentication-redesign.md)
- **Companion docs:** [agent-adr-validation-closure.md](agent-adr-validation-closure.md), [portable-tpm-gap-closure.md](portable-tpm-gap-closure.md)

---

## Phase reference

| Phase | ADR 0005 §Rollout | Key artifacts |
|-------|-------------------|---------------|
| P1 | Daemon signing oracle | `cmd/passless/src/agent/sign.rs`, `passless-core/src/agent/protocol.rs` (`SignAssertion*`) |
| P2 | MAIN-world shim + isolated-world broker + browser load | `cmd/passless/assets/agent-extension/`, `browser.rs:generate_agent_extension` |
| P3 | Delete bypassed delegated ceremony stack | `AgentCeremonyHandler`, `AgentInteractionManager` pre-auth, `agent_mode` flag, `with_shared_storage_and_pre_authorization` |
| P4 | Portable-TPM E2E | `cmd/passless/src/storage/tpm/portable/provider.rs`, swtpm |

---

## 1 · Unit tests

### P1 — Daemon signing oracle

| ID | Area | Command | Expected | Automation |
|----|------|---------|----------|------------|
| U1.1 | `clientDataJSON` canonical form | `cargo test --all-features -p passless-rs --bin passless agent::sign::tests::test_client_data_json` | Pass: no-cross-origin and cross-origin variants match byte-exact expected JSON | ✅ Fully automated |
| U1.2 | `authenticatorData` byte layout | `cargo test --all-features -p passless-rs --bin passless agent::sign::tests::test_authenticator_data_bytes` | 37 bytes; rp_id_hash ‖ flags ‖ sign_count(4 BE); flags = UP\|UV\|backup | ✅ Fully automated |
| U1.3 | Origin verification | `cargo test --all-features -p passless-rs --bin passless agent::sign::tests::test_origin_verification_*` | Exact match passes; wrong origin denied; explicit allow-list overrides | ✅ Fully automated |
| U1.4 | base64url round-trip | `cargo test --all-features -p passless-rs --bin passless agent::sign::tests::test_b64u_*` | Round-trip identity; no padding chars | ✅ Fully automated |
| U1.5 | Protocol validation bounds | `cargo test --all-features -p passless-rs --bin passless agent::protocol` | `SignAssertion` rejects empty challenge, oversized allow_credentials, oversized origin/bearer | ✅ Fully automated |
| U1.6 | `authenticatorData` soft-fido2 fixture | Add a byte-exact fixture produced from the private soft-fido2 builder's documented layout | Byte-identical 37-byte output for the same RP, flags, backup state, and count | Requires implementation |

### P2 — Extension content script

| ID | Area | Command | Expected | Automation |
|----|------|---------|----------|------------|
| U2.1 | Extension manifest schema | Parse `manifest.json` in a Node test | MV3; MAIN shim and isolated broker run at `document_start` on HTTPS frames | Fully automated |
| U2.2 | Request serialization | Run shim/broker tests with ArrayBuffer fixtures | Challenge and credential IDs retain exact bytes and unpadded base64url encoding | Requires implementation |
| U2.3 | Per-frame origin | Run shim/broker tests in top-level and subframe fixtures | Each request uses its own frame origin; page input cannot override it | Requires implementation |
| U2.4 | Native method behavior | Run wrapper tests with a fake original method | Non-WebAuthn calls pass through; handled WebAuthn failures never fall through | Requires implementation |
| U2.5 | Broker secret isolation | Run a browser fixture that probes globals, DOM, events, resources, console, and errors | Page cannot recover bearer or endpoint configuration | Requires implementation |

### P3 — Deletion of bypassed ceremony stack

| ID | Area | Command | Expected | Automation |
|----|------|---------|----------|------------|
| U3.1 | No `with_shared_storage_and_pre_authorization` | `grep -r 'with_shared_storage_and_pre_authorization' cmd/ passless-core/` | No matches | ✅ Fully automated |
| U3.2 | No `agent_mode` callback flag in ceremony path | `grep -rn 'agent_mode' cmd/passless/src/agent/ceremony.rs` | No matches (or only in isolated/confirm contexts) | ✅ Fully automated |
| U3.3 | Isolated mode still compiles and tests pass | `cargo test --all-features -p passless-rs --bin passless agent::runtime::tests` | All pass | ✅ Fully automated |
| U3.4 | Confirm-policy prompt path intact | `cargo test --all-features -p passless-rs --bin passless agent::ceremony::tests` (confirm-related tests) | All pass | ✅ Fully automated |

### P4 — TPM sign path

| ID | Area | Command | Expected | Automation |
|----|------|---------|----------|------------|
| U4.1 | Portable TPM provider sign-only (no scalar export) | `cargo test --all-features --test tpm_portable -- --test-threads=1 --ignored` | Pass; key never extracted | ⚙️ Requires swtpm |
| U4.2 | Sign handler dispatches to `CredentialKeyProvider` (not hardcoded software) | **New test needed.** Inject a mock `CredentialKeyProvider` that records calls; assert it is invoked during `SignHandler::sign` | Mock called; no raw key material in handler scope | ⚙️ Requires implementation |

---

## 2 · Integration tests

| ID | Phase | Area | Command | Expected | Automation |
|----|-------|------|---------|----------|------------|
| I1 | P1 | Sign endpoint HTTP round-trip | **New test needed.** Start `SignHttpServer::bind`, POST a valid `SignAssertionRequest` with correct bearer, parse 200 response, verify signature with public key | 200 + valid signature verifiable offline | ⚙️ Requires implementation |
| I2 | P1 | Sign endpoint auth and preflight | Exercise allowed-origin OPTIONS, valid POST, missing bearer, wrong bearer, and origin mismatch | Preflight permits only the required request; invalid requests fail before handler/key use | Requires implementation |
| I3 | P1 | Policy deny → audit event | Configure profile with RP not in allowlist; send sign request; check audit log for `PolicyDeny` with reason `rp_not_allowed` | Deny event recorded; no signature returned | ⚙️ Requires implementation |
| I4 | P1 | Grant TTL enforcement | Create grant with short TTL; wait for expiry; send sign request → 403 `no_active_grant` | Deny after TTL | ⚙️ Requires implementation |
| I5 | P1 | Credential ref enforcement | Request with credential_ref not in allowed list → 403 `credential_ref_not_allowed` | Deny + audit | ⚙️ Requires implementation |
| I6 | P1 | Signature counter increment | Two successive sign calls on same discoverable credential; second `authenticatorData` sign_count = first + 1 | Monotonic counter | ⚙️ Requires implementation |
| I7 | P1 | Constant counter mode | Set `constant_signature_counter = true`; two sign calls; both sign_count = 0 | No increment | ⚙️ Requires implementation |
| I8 | P2 | Extension loaded in browser | Launch Chromium via `generate_agent_extension` + `build_browser_command`; CDP `Runtime.evaluate` checks `navigator.credentials.get !== nativeGet` | Override active | ⚙️ Requires local Chromium |
| I9 | P2 | Extension config isolation | After browser launch, probe page-visible globals, DOM, events, resources, console, and errors | Bearer and endpoint configuration are not page-readable; broker can still reach daemon | Requires local Chromium |
| I10 | P3 | Isolated mode regression | `cargo test --all-features --test agent_config_integration` | All pass; isolated credentials still scoped | ✅ Fully automated |
| I11 | P3 | Confirm-policy human prompt | `cargo test --all-features -p passless-rs --bin passless agent::ceremony::tests` (confirm variants) | Confirm still triggers `DesktopPromptHandle` | ✅ Fully automated |
| I12 | P3 | No delegated UHID endpoint | `grep -rn 'delegated.*uhid\|uhid.*delegated' cmd/passless/src/agent/device.rs` | No delegated UHID creation path | ✅ Fully automated |
| I13 | P4 | swtpm portable sign via sign handler | **New test needed.** Provision swtpm, create portable credential, route sign request through `SignHandler` with TPM key provider, verify signature | Valid ES256 signature; key never in host memory | ⚙️ Requires swtpm + implementation |

---

## 3 · Build / Clippy / Test gate

| ID | Command | Expected | Automation |
|----|---------|----------|------------|
| B1 | `cargo fmt --all -- --check` | Exit 0 | ✅ CI |
| B2 | `cargo clippy --all-targets --all-features -- -D warnings` | Exit 0, zero warnings | ✅ CI |
| B3 | `cargo test --all-features` | All unit + integration tests pass | ✅ CI |
| B4 | `cargo build --release --all-features` | Exit 0; binary produced | ✅ CI |
| B5 | `make test-agent-validation` | All 12 phases pass (see `test-deterministic.sh`) | ✅ CI (deterministic subset) |
| B6 | `shellcheck -S warning tools/agent-validation/**/*.sh` | Exit 0 | ✅ CI |
| B7 | `make check-doc-links` | No broken internal links | ✅ CI |
| B8 | `pre-commit run --all-files` | All hooks pass | ✅ CI |

---

## 4 · Browser extension validation

| ID | Area | Procedure | Expected observation | Automation |
|----|------|-----------|---------------------|------------|
| BX1 | Extension loads without error | Launch Chromium with `--load-extension=<ext_dir>`; check `chrome://extensions` via CDP for `passless-agent` status=enabled | Extension enabled, no errors | ⚙️ Requires local Chromium + Xvfb |
| BX2 | MAIN-world injection | CDP `Runtime.evaluate` on a `https://` page: `typeof navigator.credentials.get` | `"function"` (overridden, not native) | ⚙️ Requires local Chromium |
| BX3 | Non-WebAuthn passthrough | Navigate to page; call `navigator.credentials.get({})` (no publicKey) | Falls through to native; no daemon call | ⚙️ Requires local Chromium |
| BX4 | Broker authentication | Have the test endpoint report whether it received a valid bearer without recording its value | Valid broker request authenticates; a page-forged request without the token is rejected | Requires local Chromium |
| BX5 | Extension file permissions | After `generate_agent_extension`, `stat -c '%a'` on config.js | `600` | ✅ Automatable in unit test |
| BX6 | Extension dir ownership | After generation, `stat -c '%U:%G'` on extension dir | Matches target UID:GID | ⚙️ Requires privileged setup |

---

## 5 · Negative security tests

| ID | Area | Procedure | Expected | Automation |
|----|------|-----------|----------|------------|
| S1 | Missing bearer | POST to sign endpoint without `Authorization` header | 401 | ⚙️ Requires implementation |
| S2 | Wrong bearer | POST with `Bearer invalid_token` | 401 | ⚙️ Requires implementation |
| S3 | Origin mismatch | POST with `Origin: https://evil.com` but `origin` field = `https://rp.example.com` in body | 400 (header/body mismatch check at `sign.rs:301-306`) | ⚙️ Requires implementation |
| S4 | Wrong RP ID | Sign request with `rp_id: "evil.com"` but credential belongs to `example.com` | 403 `origin_denied` or `rp_not_allowed` | ⚙️ Requires implementation |
| S5 | Expired grant | Sign request after grant TTL elapsed | 403 `no_active_grant` | ⚙️ Requires implementation |
| S6 | Unauthorized credential ref | Sign request with credential_ref not in profile's allowed list | 403 `credential_ref_not_allowed` | ⚙️ Requires implementation |
| S7 | No credential refs configured | Profile with `credential_refs = None` | 403 `no_credential_refs` | ⚙️ Requires implementation |
| S8 | Policy not `allow` | RP rule with `authorization: "confirm"` → sign endpoint should reject (not auto-approve) | 403 `authorization_not_allow` | ⚙️ Requires implementation |
| S9 | Oversized payload | `allow_credentials` > `MAX_ALLOW_CREDENTIALS` (64) | Validation error before any side effect | ✅ Covered by protocol validation tests |
| S10 | Null bytes in request | Send request body with `\0` bytes | Rejected at parse or validation | ⚙️ Requires implementation |
| S11 | Replay attack | Submit identical sign request twice; second must fail (grant consumed or counter check) | Second request denied or idempotent with same counter | ⚙️ Requires implementation |
| S12 | Cross-origin credential theft | Content script on `https://evil.com` tries to sign for `rp_id: "example.com"` | Origin verification fails; 403 | ⚙️ Requires implementation |
| S13 | Extension config leakage | Probe page-visible globals, DOM, events, resources, console, and errors on allowed and unrelated origins | Bearer and endpoint configuration are not page-readable on any origin | Requires local Chromium |

---

## 6 · Real-RP E2E at `https://tea.millaguie.net/`

**Prerequisites:**
- Passless daemon running with agent enabled
- Chromium installed locally
- Xvfb or real display session
- Network access to `tea.millaguie.net`
- Existing credential registered at the RP for the configured profile
- Grant active for the credential
- Profile policy: `allow` rule for `tea.millaguie.net`

| ID | Area | Procedure | Expected observation | Automation |
|----|------|-----------|---------------------|------------|
| E1 | Full autonomous login | 1. Start daemon with sign endpoint active<br>2. Launch Chromium via passless browser lease with extension loaded<br>3. Navigate to `https://tea.millaguie.net/` login<br>4. Trigger passkey authentication<br>5. Observe page transition | Login succeeds; no native credential modal appears; no desktop notification shown | ❌ Requires configured local environment |
| E2 | `clientDataJSON` correctness | After E1, intercept the sign response; decode `client_data_json_b64u`; verify `origin` field = `https://tea.millaguie.net` and `challenge` matches RP challenge | Origin matches exactly; challenge matches | ❌ Requires configured local environment |
| E3 | Signature verification by RP | RP accepts the assertion and completes authentication | HTTP 200 / redirect to dashboard; session cookie set | ❌ Requires configured local environment |
| E4 | No native modal | Record screen (or CDP `Page.javascriptDialogOpening` events) during E1 | Zero modal/dialog events | ❌ Requires configured local environment |
| E5 | No desktop notification | Monitor D-Bus `org.freedesktop.Notifications` during E1 (allow-policy rule) | Zero `Notify` calls for the sign operation | ❌ Requires configured local environment |
| E6 | Audit trail | After E1, check audit log | `PolicyAllow` event recorded with correct profile_id, rp_id, action=authenticate | ❌ Requires configured local environment |
| E7 | Wrong RP denied | Navigate to a different site; trigger WebAuthn for unallowed RP | `NotAllowedError` thrown in page; daemon audit shows `PolicyDeny` | ❌ Requires configured local environment |
| E8 | Grant expiry mid-session | Let grant TTL expire; trigger another auth attempt | Denied; audit shows `no_active_grant` | ❌ Requires configured local environment |

---

## 7 · No-native-dialog / no-notification evidence

| ID | Area | Procedure | Expected evidence | Automation |
|----|------|-----------|-------------------|------------|
| N1 | No CDP dialog events | During E1, capture all CDP events; filter `Page.javascriptDialogOpening`, `Page.javascriptDialogClosed` | Zero events | ⚙️ Scriptable with CDP driver |
| N2 | No D-Bus Notify calls | Run `dbus-monitor --session "interface='org.freedesktop.Notifications'"` during E1 | No `Notify` method calls for allow-policy operations | ⚙️ Scriptable in Xvfb session |
| N3 | No UHID device created | `ls /dev/uhid*` before and during delegated session; `dmesg | grep uhid` | No new UHID devices for delegated autonomy | ✅ Automatable |
| N4 | No hidraw node for delegated | `ls /dev/hidraw*` before and during | No new hidraw nodes for delegated path | ✅ Automatable |
| N5 | Notification suppression in logs | Grep daemon logs for `notify_rust\|DesktopPromptHandle` during allow-policy autonomous sign | No notification dispatch log lines | ✅ Automatable |

---

## 8 · Audit / grant / counter checks

| ID | Area | Procedure | Expected | Automation |
|----|------|-----------|----------|------------|
| A1 | Audit allow event | Sign via extension path; inspect audit file | `PolicyAllow` with profile_id, rp_id, action, timestamp | ⚙️ Requires implementation |
| A2 | Audit deny events | Trigger each deny scenario (S3–S8); inspect audit | `PolicyDeny` with specific reason codes | ⚙️ Requires implementation |
| A3 | Grant consumed / TTL respected | Create grant with 10s TTL; sign at t=0 (success), sign at t=11 (denied) | Allow then deny | ⚙️ Requires implementation |
| A4 | Counter monotonicity | 5 successive signs; extract sign_count from each `authenticatorData` | Strictly increasing (or constant if `constant_signature_counter`) | ⚙️ Requires implementation |
| A5 | Counter persistence across daemon restart | Sign twice; restart daemon; sign again; verify counter continues from last value | No counter rollback | ⚙️ Requires implementation |
| A6 | Concurrent sign serialization | Two simultaneous sign requests for same credential | One succeeds first; second gets updated counter; no data loss | ⚙️ Requires implementation |
| A7 | Audit pre-write blocks sign | Make audit path read-only; attempt sign | Sign fails; no key use occurs | ⚙️ Requires implementation |

---

## 9 · Isolated-mode regression

| ID | Area | Procedure | Expected | Automation |
|----|------|-----------|----------|------------|
| ISO1 | Isolated credential registration | `cargo test --all-features -p passless-rs --bin passless agent::ceremony::tests` (isolated register variants) | Pass | ✅ Fully automated |
| ISO2 | Isolated credential assertion | Same, assertion variants | Pass | ✅ Fully automated |
| ISO3 | Isolated storage scoping | `cargo test --all-features -p passless-rs --bin passless agent::storage` | Isolated reads gated by ceremony scope (`agent/storage.rs:743-844`) | ✅ Fully automated |
| ISO4 | Human endpoint cannot use isolated cred | `cargo test --all-features -p passless-rs --bin passless agent::runtime::tests` (cross-mode denial) | Denial | ✅ Fully automated |
| ISO5 | Another agent profile cannot use isolated cred | Same suite, cross-profile denial | Denial | ✅ Fully automated |
| ISO6 | Isolated credential revocation | Revoke locally; subsequent auth fails | Denial | ✅ Fully automated |
| ISO7 | Full deterministic validation | `make test-agent-validation` | All phases pass including isolated ceremony stages | ✅ Fully automated |

---

## 10 · Confirm-policy denial

| ID | Area | Procedure | Expected | Automation |
|----|------|-----------|----------|------------|
| C1 | Confirm rule blocks autonomous sign | Configure profile with `authorization: "confirm"` for RP; send sign request to extension endpoint | 403 `authorization_not_allow`; daemon does NOT auto-approve | ⚙️ Requires implementation |
| C2 | Confirm triggers human prompt | Same config; trigger via browser (non-autonomous path) | `DesktopPromptHandle` notification appears; requires explicit user action | ⚙️ Requires Xvfb + notification daemon |
| C3 | Confirm denial propagates | Trigger confirm; deny at prompt | `NotAllowedError` in page; audit `PolicyDeny` | ⚙️ Requires Xvfb |
| C4 | Confirm timeout | Trigger confirm; do not act; wait for timeout | Denied; audit `PolicyDeny` with timeout reason | ⚙️ Requires Xvfb |
| C5 | Confirm premature action | Trigger confirm; act before minimum review delay | Denied (fail-closed) | ⚙️ Requires Xvfb |

---

## 11 · Portable TPM E2E

**Prerequisites:**
- `swtpm` installed and runnable
- Portable TPM parent provisioned on swtpm instance
- Credential created via portable TPM backend
- Daemon configured with `--backend-type tpm --tpm-portable`

| ID | Area | Procedure | Expected | Automation |
|----|------|-----------|----------|------------|
| T1 | swtpm provision | Start a dedicated per-run swtpm with unique state, ports, PID file, and cleanup trap; provision through its TCTI | Parent provisioned without stopping or reusing unrelated swtpm processes | Requires swtpm |
| T2 | Portable credential creation | Register credential via portable TPM backend | Credential created; key is TPM-resident | ⚙️ Requires swtpm |
| T3 | Sign via extension path with TPM key | Send `SignAssertionRequest` through sign endpoint; daemon dispatches to `TpmCredentialKeyProvider` | Valid ES256 signature; `TPM2_Sign` invoked | ⚙️ Requires swtpm + implementation |
| T4 | Key non-extractable contract | Inspect the stored credential type and provider trace; assert no software scalar or export API is used and signing reaches `TPM2_Sign` | Portable TPM key reference is stored and provider signing succeeds without an export path | Requires swtpm |
| T5 | CDP virtual-authenticator cannot replicate | Attempt to inject TPM credential into CDP virtual authenticator | Impossible: no PKCS#8 export; injection fails | ✅ Expected failure (documented) |
| T6 | Real-RP E2E with TPM | Repeat E1–E3 with TPM-backed credential at `tea.millaguie.net` | Login succeeds; RP accepts; no modal | ❌ Requires configured local environment + swtpm |
| T7 | TPM E2E existing suite | `make test-e2e-tpm` | All `test_tpm_*` pass | ⚙️ Requires swtpm |
| T8 | Portable TPM unit suite | `cargo test --all-features --test tpm_portable --test tpm_portable_storage -- --test-threads=1 --ignored` | All pass | ⚙️ Requires swtpm |
| T9 | Portable TPM error handling | `cargo test --all-features --test tpm_portable_parent_errors --test tpm_portable_robustness --test tpm_portable_capability` | All pass | ⚙️ Requires swtpm |

---

## 12 · Rollback / debug evidence collection

| ID | Scenario | Evidence to collect | Command / method |
|----|----------|-------------------|------------------|
| R1 | Sign endpoint failure | Daemon stderr, audit log, sign request/response bodies | `journalctl --user -u passless --since "5 min ago"`; `cat target/agent-validation/<run-id>/audit/*` |
| R2 | Extension load failure | Chromium stderr, `chrome://extensions` state, CDP error events | Chromium stderr capture; CDP `Runtime.consoleAPICalled` |
| R3 | clientDataJSON mismatch | Decoded `client_data_json_b64u` from sign response vs RP-expected | Decode base64url; diff origin/challenge fields |
| R4 | TPM sign failure | swtpm log, TPM RC error code, provider trace | `TPM2TOOLS_LOG_LEVEL=DEBUG`; swtpm stdout capture |
| R5 | Policy deny investigation | Audit deny event with reason code | `jq 'select(.action=="policy_deny")' < audit log` |
| R6 | Grant/TTL issue | Grant registry state, timestamps | Daemon debug log with `RUST_LOG=passless::agent::grant=debug` |
| R7 | Full rollback rehearsal | In a disposable worktree at the pre-ADR commit, verify the human E2E still passes | Create a separate `git worktree`; do not alter the active dirty worktree |
| R8 | Counter anomaly | Credential storage dump (sign_count field) | `passless` storage inspection; compare expected vs actual |

---

## Automation summary

| Category | Fully automated (CI) | Requires local environment | Requires implementation |
|----------|---------------------|---------------------------|------------------------|
| Unit tests (P1–P3) | U1.1–U1.5, U2.1–U2.4, U3.1–U3.4 | — | U1.6 |
| Unit tests (P4) | — | U4.1 | U4.2 |
| Integration tests | I10–I12 | I8, I9, I13 | I1–I7 |
| Build/clippy/test | B1–B8 | — | — |
| Extension validation | BX5 | BX1–BX4, BX6 | — |
| Negative security | S9 | S1–S8, S10–S13 | All need test harness |
| Real-RP E2E | — | E1–E8 | — |
| No-dialog evidence | N3–N5 | N1, N2 | — |
| Audit/grant/counter | — | A1–A7 | All need test harness |
| Isolated regression | ISO1–ISO7 | — | — |
| Confirm-policy | — | C1–C5 | All need test harness |
| Portable TPM | — | T1–T4, T6–T9 | T3 (sign via extension) |

---

## Prerequisites checklist

- [ ] Rust toolchain (stable, edition 2024)
- [ ] `cargo`, `shellcheck`, `node`, `jq`, `pass`, `gpg`, `dbus-daemon`, `swtpm`
- [ ] Chromium or chromium-browser installed
- [ ] Xvfb + notification daemon (dunst or reference impl) for Tier 2 browser tests
- [ ] Network access to `https://tea.millaguie.net/` for real-RP E2E
- [ ] swtpm for TPM tests (`pkill -x swtpm` before each run)
- [ ] `PASSLESS_E2E_AUTO_ACCEPT_UV` and `PASSLESS_E2E_AUTO_ACCEPT_STORAGE` **unset**
- [ ] Clean git working tree on the ADR 0005 implementation branch
- [ ] Sufficient disk for `target/agent-validation/<run-id>/` evidence directory
