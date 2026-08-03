# ADR 0005 — Full-Implementation Verification Matrix

- **Status:** Verification plan (software-credential MVP verified against real RP)
- **Date:** 2026-08-02
- **Covers:** All four rollout phases of [ADR 0005](../decisions/0005-delegated-autonomous-authentication-redesign.md)
- **Companion docs:** [agent-adr-validation-closure.md](agent-adr-validation-closure.md), [portable-tpm-gap-closure.md](portable-tpm-gap-closure.md)

---

## Phase reference

| Phase | ADR 0005 §Rollout | Key artifacts |
|-------|-------------------|---------------|
| P1 | Daemon signing oracle | `cmd/passless/src/agent/sign.rs`, `passless-core/src/agent/protocol.rs` (`SignAssertion*`) |
| P2 | MAIN-world shim + isolated-world broker + browser load | `cmd/passless/assets/agent-extension/`, `browser.rs:generate_agent_extension` |
| P3 | Delete bypassed delegated ceremony stack | Pre-auth mint + `with_shared_storage_and_pre_authorization` removed; delegated UHID endpoint arms and `agent_mode` safety net retained for isolated/confirm |
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
| U1.6 | `authenticatorData` soft-fido2 fixture | `agent::sign::tests::test_authenticator_data_*` | Byte-identical 37-byte output for the same RP, flags, backup state, and count | ✅ Fully automated |

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
| I1 | P1 | Sign endpoint HTTP round-trip | `agent::sign::tests::integration_tests::http_sign_full_response_structure` | 200 + valid signature verifiable offline | ✅ Fully automated |
| I2 | P1 | Sign endpoint auth and preflight | `http_auth_preflight_then_sign` + existing `test_http_options_sign_preflight` / `test_http_missing_bearer` / `test_http_unknown_bearer_401` / `test_http_unbound_bearer_401` / `test_http_revoked_bearer_401` | Preflight permits only the required request; invalid requests fail before handler/key use | ✅ Fully automated |
| I3 | P1 | Policy deny → audit event | `audit_and_policy_tests::audit_deny_event_on_rp_mismatch` (+ `http_policy_deny_returns_403`) | Deny event recorded; no signature returned | ✅ Fully automated |
| I4 | P1 | Grant TTL enforcement | `integration_tests::http_grant_ttl_enforced` | Deny after TTL | ✅ Fully automated |
| I5 | P1 | Credential ref enforcement | `integration_tests::http_credential_ref_enforced` (+ `http_unauthorized_credential_denied`) | Deny + audit | ✅ Fully automated |
| I6 | P1 | Signature counter increment | `integration_tests::http_counter_increment_monotonic` | Monotonic counter | ✅ Fully automated |
| I7 | P1 | Constant counter mode | `audit_and_policy_tests::counter_zero_in_constant_mode_response` | No increment | ✅ Fully automated |
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
| S1 | Missing bearer | POST to sign endpoint without `Authorization` header | 401 | ✅ Fully automated (`test_http_missing_bearer`) |
| S2 | Wrong bearer | POST with `Bearer invalid_token` | 401 | ✅ Fully automated (`test_http_unknown_bearer_401`, `test_http_revoked_bearer_401`, `http_bearer_not_prefix_match`, `http_wrong_auth_scheme`) |
| S3 | Origin mismatch | POST with body `origin` not matching RP ID | 403 `origin_invalid` | ✅ Fully automated (`http_origin_mismatch_denied`, `audit_deny_event_on_origin_mismatch`) |
| S4 | Wrong RP ID | Sign request with `rp_id` not in grant | 403 `rp_id_not_match` | ✅ Fully automated (`http_wrong_rp_id_denied`, `audit_deny_event_on_rp_mismatch`) |
| S5 | Expired grant | Sign request after grant TTL elapsed | 403 `grant_expired` | ✅ Fully automated (`http_grant_ttl_enforced`, `audit_deny_event_on_expired_grant`) |
| S6 | Unauthorized credential ref | Sign request with allow_credentials not matching grant credential | 403 `allow_credentials_mismatch` | ✅ Fully automated (`http_unauthorized_credential_denied`, `audit_deny_event_on_credential_mismatch`) |
| S7 | No credential refs configured | Profile with `credential_refs = None` | 403 `no_credential_refs` | ⚙️ Requires implementation |
| S8 | Policy not `allow` | RP rule with `authorization: "confirm"` → sign endpoint rejects (not auto-approve) | 403 `action_not_allowed` | ✅ Fully automated (`confirm_policy_blocks_autonomous_sign`, `deny_authorization_blocks_sign`, `confirm_policy_deny_audit_event`) |
| S9 | Oversized payload | `allow_credentials` > `MAX_ALLOW_CREDENTIALS` (64) | Validation error before any side effect | ✅ Covered by protocol validation tests |
| S10 | Null bytes in request | Send request body with `\0` bytes | Rejected at parse or validation | ⚙️ Requires implementation |
| S11 | Replay attack | Submit identical sign request twice | Counter increments (monotonic mode); no token/credential leak | ✅ Fully automated (`http_replay_attack_same_challenge`) |
| S12 | Cross-origin credential theft | Content script on `https://evil.com` tries to sign for `rp_id: "example.com"` | Origin verification fails; 403 | ✅ Fully automated (`http_cross_origin_theft_attempt`) |
| S13 | Extension config leakage | Probe page-visible globals, DOM, events, resources, console, and errors on allowed and unrelated origins | Bearer and endpoint configuration are not page-readable on any origin | Requires local Chromium |

---

## 6 · Real-RP E2E

**Prerequisites:**
- Passless daemon running with agent enabled
- Chromium installed locally
- Xvfb or real display session
- Network access to the configured real RP (`AV_REAL_RP_URL`)
- Existing credential registered at the RP for the configured profile
- Grant active for the credential
- Profile policy: `allow` rule for the configured RP

| ID | Area | Procedure | Expected observation | Automation |
|----|------|-----------|---------------------|------------|
| E1 | Full autonomous login | 1. Start daemon with sign endpoint active<br>2. Launch Chromium via passless browser lease with extension loaded<br>3. Navigate to the configured real RP login page<br>4. Trigger passkey authentication<br>5. Observe page transition | Login succeeds; no native credential modal appears; no desktop notification shown | ✅ Verified 2026-08-03: dashboard loaded; extension override active; daemon sign endpoint served the assertion |
| E2 | `clientDataJSON` correctness | After E1, intercept the sign response; decode `client_data_json_b64u`; verify `origin` field matches the configured RP and `challenge` matches RP challenge | Origin matches exactly; challenge matches | ✅ Verified: sign endpoint response `client_data_json_b64u` decoded with matching origin; RP accepted the assertion |
| E3 | Signature verification by RP | RP accepts the assertion and completes authentication | HTTP 200 / redirect to dashboard; session cookie set | ✅ Verified 2026-08-03: navigated to dashboard after passkey click |
| E4 | No native modal | Record screen (or CDP `Page.javascriptDialogOpening` events) during E1 | Zero modal/dialog events | ⚙️ Verified no forbidden CDP WebAuthn methods; dialog capture scriptable with CDP driver |
| E5 | No desktop notification | Monitor D-Bus `org.freedesktop.Notifications` during E1 (allow-policy rule) | Zero `Notify` calls for the sign operation | ⚙️ Scriptable in Xvfb session |
| E6 | Audit trail | After E1, check audit log | `PolicyAllow` event recorded with correct profile_id, rp_id, action=authenticate | ✅ Verified 2026-08-03: audit shows `policy.allow` for the delegated profile and configured RP |
| E7 | Wrong RP denied | Navigate to a different site; trigger WebAuthn for unallowed RP | `NotAllowedError` thrown in page; daemon audit shows `PolicyDeny` | ✅ Covered by `http_cross_origin_theft_attempt` + `audit_deny_event_on_rp_mismatch` |
| E8 | Grant expiry mid-session | Let grant TTL expire; trigger another auth attempt | Denied; audit shows `no_active_grant` | ✅ Covered by `http_grant_ttl_enforced` + `audit_deny_event_on_expired_grant` |

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
| A1 | Audit allow event | Sign via sign handler; inspect audit | `PolicyAllow` with profile_id, rp_id, action, timestamp | ✅ Fully automated (`audit_allow_event_on_successful_sign`) |
| A2 | Audit deny events | Trigger each deny scenario; inspect audit | `PolicyDeny` with specific reason codes | ✅ Fully automated (`audit_deny_event_on_origin_mismatch`, `audit_deny_event_on_expired_grant`, `audit_deny_event_on_revoked_grant`, `audit_deny_event_on_rp_mismatch`, `audit_deny_event_on_credential_mismatch`, `confirm_policy_deny_audit_event`) |
| A3 | Grant consumed / TTL respected | Create grant with short TTL; sign at t=0 (success), sign after expiry (denied) | Allow then deny | ✅ Fully automated (`audit_deny_event_on_expired_grant`, `http_grant_ttl_enforced`) |
| A4 | Counter monotonicity | Successive signs; extract sign_count from each `authenticatorData` | Strictly increasing (or constant if `constant_signature_counter`) | ✅ Fully automated (`monotonic_sequential_counter`, `counter_increments_in_monotonic_mode_response`, `counter_zero_in_constant_mode_response`, `http_counter_increment_monotonic`) |
| A5 | Counter persistence | Sign twice; sign again; counter continues from last value | No counter rollback | ✅ Fully automated (`persisted_counter_visible_after_reconstruct`) |
| A6 | Concurrent sign serialization | Two simultaneous sign requests for same credential | Serialized; no data loss | ✅ Fully automated (`concurrent_counter_serialization`) |
| A7 | Audit pre-write blocks sign | Make audit recording fail; attempt sign | Sign fails; no key use occurs | ✅ Fully automated (`audit_pre_write_blocks_sign`) |

### Cancellation / cleanup regression (CLOSES the plan's former "Current blocker")

| ID | Area | Procedure | Expected | Automation |
|----|------|-----------|----------|------------|
| CR1 | Cancel revokes resolved grant | Delegate, approve grant, cancel; resolve the grant | Grant no longer active | ✅ Fully automated (`agent::runtime::tests::cancel_after_approval_revokes_resolved_grant`) |
| CR2 | Cancel revokes bearer | After cancel, inspect `SignContextRegistry` for the cancelled lease | No entries remain | ✅ Fully automated (`cancel_after_approval_revokes_bearer_from_registry`) |
| CR3 | Cancel leaves no usable sign context | After cancel, `lookup_bound` for the lease token | None | ✅ Fully automated (`cancel_after_approval_leaves_no_usable_sign_context`) |
| CR4 | Sign denied after cancel | Attempt sign with the cancelled lease's context | Denied | ✅ Fully automated (`sign_denied_after_cancel_revokes_grant`) |
| CR5 | Expired grant unusable | Grant past TTL via registry path | Denied | ✅ Fully automated (`expired_grant_is_not_usable_for_signing_via_registry`) |
| CR6 | Explicit revocation denies | Revoke via `PolicyRuntime`; attempt sign | Denied | ✅ Fully automated (`sign_denied_after_explicit_revocation_via_policy`) |

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
| C1 | Confirm rule blocks autonomous sign | Configure profile with `authorization: "confirm"` for RP; send sign request | 403 `action_not_allowed`; daemon does NOT auto-approve | ✅ Fully automated (`confirm_policy_blocks_autonomous_sign`, `confirm_policy_deny_audit_event`) |
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
| T6 | Real-RP E2E with TPM | Repeat E1–E3 with TPM-backed credential at the configured real RP | Login succeeds; RP accepts; no modal | ❌ Requires configured local environment + swtpm |
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
| Unit tests (P1–P3) | U1.1–U1.6, U2.1–U2.4, U3.1–U3.4 | — | — |
| Unit tests (P4) | — | U4.1 | U4.2 |
| Integration tests | I1–I7, I10–I12 | I8, I9, I13 | — |
| Build/clippy/test | B1–B8 | — | — |
| Extension validation | BX5 | BX1–BX4, BX6 | — |
| Negative security | S1–S6, S8, S9, S11, S12 | S13 | S7, S10 |
| Real-RP E2E | E1–E3, E6 (verified 2026-08-03) | E4, E5 | — |
| No-dialog evidence | N3–N5 | N1, N2 | — |
| Audit/grant/counter | A1–A7 | — | — |
| Cancellation/cleanup regression | CR1–CR6 | — | — |
| Isolated regression | ISO1–ISO7 | — | — |
| Confirm-policy | C1 | C2–C5 | — |
| Portable TPM | — | T1–T4, T6–T9 | T3 (sign via extension) |

---

## Prerequisites checklist

- [ ] Rust toolchain (stable, edition 2024)
- [ ] `cargo`, `shellcheck`, `node`, `jq`, `pass`, `gpg`, `dbus-daemon`, `swtpm`
- [ ] Chromium or chromium-browser installed
- [ ] Xvfb + notification daemon (dunst or reference impl) for Tier 2 browser tests
- [ ] Network access to the configured real RP (`AV_REAL_RP_URL`) for real-RP E2E
- [ ] swtpm for TPM tests (`pkill -x swtpm` before each run)
- [ ] `PASSLESS_E2E_AUTO_ACCEPT_UV` and `PASSLESS_E2E_AUTO_ACCEPT_STORAGE` **unset**
- [ ] Clean git working tree on the ADR 0005 implementation branch
- [ ] Sufficient disk for `target/agent-validation/<run-id>/` evidence directory
