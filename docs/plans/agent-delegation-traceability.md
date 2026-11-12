# ADR 0014 traceability audit

Audited at `5693572` (read-only, nothing run); the gaps it found were closed afterwards and the rows below carry the
closed status (the "Closed" notes name the test or the ADR amendment). This is the traceability artifact of the
[plan's Final gate](agent-delegation-implementation.md#final-gate).
Unit test names are backticked and were checked against a grep of every `#[test]`/`#[tokio::test]` fn in `cmd/` and
`passless-core/` (the check is re-run at the end of this file). `js:N` is a `test(...)` at line N of
`cmd/passless/tests/agent_extension_behavioral.js` (run by Rust test `test_agent_extension_behavioral_node_suite`).
E2E ids were checked against `scenario({ id: ... })` in `tests/agent-e2e/scenarios/*.test.js`. "Ph" = implementing phase
from the plan (`pre` = existed before ADR 0014). Status: OK / NO-TEST / NO-CODE / DIVERGES. Paths are relative to the repo
root; `A/` = `cmd/passless/src/agent/`, `C/` = `passless-core/src/agent/`, `T/` = `cmd/passless/src/agent/transport/`.

E2E pipe-mode note: the E2E ids above run in port mode (the harness default) unless a row says otherwise; a scenario marked `exposeModes: ['port', 'pipe']` also runs in
pipe mode (`AGENT_E2E_EXPOSE=pipe|all`, ADR 0014 section 4.3's default), driven through `browser-control` (`tests/agent-e2e/lib/pipe-driver.js`), and E2E-52 to E2E-54 are pipe-only.

E2E evidence caveat (applies to every E2E column): the scenarios exist and are titled, but `tests/agent-e2e/BASELINE.md` records
a matrix run only up to P7. P8 to P11 scenarios (E2E-32, 33, 34 to 37, 41, 45/cdp-context, 46, 47/unloadable, ...) are "E2E pending
orchestrator run" in the plan's progress log. Existence is verified here, a green run is not.

## §1-§3 Goals, non-goals, trust model

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| G-01 | Agent support disabled by default (inv 1) | pre | C/config.rs:1177 | `test_agent_config_default_disabled`, `test_no_agents_section_backward_compatible` | | OK | |
| G-02 | Human path unaffected by agent config or failure (inv 23) | P2 | cmd/passless/src/main.rs:231 | `reload_of_an_invalid_file_keeps_the_old_generation`, `invalid_legacy_rule_does_not_break_load_when_agents_disabled` | E2E-44, E2E-43 | OK | startup failure logs "human path remains available" |
| G-03 | Keys stay in daemon storage/TPM; daemon is the only signer; no key/PIN/raw-assertion API to agent | pre | C/protocol.rs:455 (principal request set has no signing request) | `json_envelope_credential_list_no_secrets`, `json_envelope_has_no_secrets`, `test_no_forbidden_field_names_in_any_event` | E2E-16 | OK | |
| G-04 | Every operation authorized from admin-owned policy, re-checked immediately before key use | P5 | A/sign.rs:1870 | `changed_reload_revokes_an_in_flight_operation_before_key_use`, `a_revocation_after_the_recheck_waits_for_key_use_and_then_holds`, `test_revoked_before_key_use_generates_nothing` | E2E-31 | OK | |
| G-05 | Durable audit before credential creation/use, evidence labelled `agent` | pre/P8 | A/sign.rs:1402 | `audit_pre_write_blocks_sign`, `a_successful_sign_is_one_reservation_and_one_terminal_record_with_every_field` | E2E-32 | OK | |
| G-06 | Fail closed on missing policy, routing, storage, audit, isolation | P4 | C/resolve.rs:126 | `default_deny_without_rules_or_for_unlisted_rp`, `missing_rule_action_denies`, `corrupt_store_disables_grants`, `test_circuit_breaker_permanent` | E2E-04 | OK | |
| T-01 | Principal auth = 256-bit launcher capability + peer creds + process identity + ns + cgroup + ancestry | pre | A/launcher.rs:99 | `test_capability_size_is_256_bits`, `test_verify_identity_fields_all_wrong`, `test_verify_process_ancestry_found`, `test_verify_peer_identity_wrong_uid` | | OK | copied capability outside boundary: `test_verify_identity_fields_wrong_cgroup`, `..._wrong_ns_inodes` |
| T-02 | Principals cannot use the administrative interface (separate admin/principal interfaces) | pre | A/ipc.rs:528 | `test_admin_socket_rejects_principal_frame`, `test_principal_socket_rejects_admin_frame`, `test_handler_traits_are_separate_types`, `admin_request_type_cannot_be_principal_request` | | OK | |
| T-03 | Daemon bearer only in the extension service worker, never visible to page JS | P6 | cmd/passless/assets/agent-extension/worker.js:15 | `test_generated_bearer_is_only_in_the_worker`, `js:982` | E2E-16 | OK | |
| T-04 | Principal never sets policy or approves escalations | P7 | C/protocol.rs:455 | `test_principal_cannot_approve`, `role_separation_admin_vs_principal` | E2E-29 | OK | see H-01 for the "no API/CLI approves" negative |

## §4 Architecture

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| D-01 | One daemon owns backends/policy/prompt/audit; agents get no storage path, handle or generic signing API | pre | C/protocol.rs:455 | `json_envelope_credential_list_no_secrets` | E2E-02 | OK | absence of a signing request in `PrincipalRequest` verified by reading the enum |
| D-02 | Principal interface = health, browser lifecycle, status, cancellation, non-secret isolated credential metadata; sign socket separate | pre/P6 | C/protocol.rs:455 | `test_principal_ping_roundtrip`, `principal_validate_browser_control_empty_json` | E2E-34 | OK | |
| D-03 | Runtime manifest durably recorded before launch (session, lease, PID, start identity, cgroup, profile path; no secrets) | pre | A/browser.rs:1214 | `test_manifest_atomic_write`, `test_manager_launch_creates_dirs_and_manifest`, `test_manifest_serialization_roundtrip` | | OK | |
| D-04 | Startup recovery kills an orphan only after start-identity and cgroup confirmation; quarantines its profile | pre | A/browser.rs:1824 | `test_manager_restart_recovery_kill_identity_match`, `test_manager_restart_recovery_kill_pid_mismatch`, `test_manager_restart_recovery_kill_start_time_mismatch`, `test_verify_process_identity_cgroup_mismatch`, `test_pid_mismatch_cleanup_quarantines` | | OK | |
| S-01 | `PrincipalSessionId` generated by Passless, not from a harness label | pre | C/ids.rs:134 | `test_principal_session_id_creation`, `test_principal_session_id_parse_rejects_non_hex` | | OK | |
| S-02 | `max_concurrent_sessions` (default 1) bounds live principals per profile | pre | A/runtime/gates.rs:13 (call at runtime.rs:2029) | `max_concurrent_sessions_zero_rejected`, `the_session_limit_refuses_the_session_past_the_maximum`, `zero_means_unlimited_only_for_profile_scope` | | OK | Closed: the refusal is a pure function, tested for the `Conflict` error and the 0 = unlimited rule |
| S-03 | `browser_scope = "session"` default: one lease per principal session, reused only by its owner | pre/P10 | A/runtime.rs:372 | `cross_session_id_mismatch_detected`, `shared_owner_exit_closes_the_browser_even_when_another_session_remains`, `browser_scope_serde_roundtrip` | E2E-46 | OK | E2E-46/session-scope covers B1 |
| S-04 | Each lease has own runtime dir and `--user-data-dir`; no sync, saved passwords, platform passkeys, copied profile | pre | A/browser.rs:2699 | `test_build_browser_command_pipe_mode`, `test_create_lease_dir_atomic`, `test_lease_layout_keeps_daemon_written_directories_daemon_owned` | | OK | `--no-first-run`, `--disable-sync` at browser.rs:2700-2702 |
| S-05 | Session end/expiry/revocation revokes lease and bearer, terminates Chromium, cleans profile | pre/P3 | A/browser.rs:1297 | `test_manager_principal_exit`, `test_manager_revoke_active`, `test_full_lifecycle_launch_revoke_terminate_cleanup`, `revoke_by_lease_covers_sign_and_registration_bearers_of_one_token` | E2E-11, E2E-31 (pipe mode: E2E-52, E2E-54) | OK | |
| S-06 | Profile that fails cleanup is quarantined and never reused | pre | A/browser.rs:3439 | `test_pid_mismatch_cleanup_quarantines`, `test_quarantine_path_unique`, `test_extension_quarantine_contains_worker_token_on_cleanup_failure` | | OK | |
| S-07 | Chrome for Testing detected from `--version` (never UA); branded check must not match the CfT string | P10 | A/browser_select.rs:70 | `versions_are_classified_and_the_branded_check_does_not_match_chrome_for_testing` | E2E-41 | OK | |
| S-08 | Branded Chrome and `chrome-headless-shell` rejected at launch with actionable error | P10 | A/browser_select.rs:466 | `a_refused_binary_gets_an_actionable_message_and_is_never_run_blindly`, `branded_chrome_is_recognised_by_name_or_install_path` | E2E-41 | OK | |
| S-09 | headless-shell recognised by binary name or path component `headless-shell`/`headless_shell`, symlink target included | P10 | A/browser_select.rs:281 | `headless_shell_is_recognised_by_name_or_install_path` | E2E-41 | OK | |
| S-10 | Distinct-UID: only root-owned, principal-unwritable binaries (binary and every parent dir) | P10 | A/browser_select.rs:219 | `distinct_uid_deployments_accept_only_root_owned_unwritable_binaries` | | OK | |
| S-11 | Binary = `browser_command`, else `agents.browser_path`, else Playwright, CfT, distro `chromium` | P10 | A/browser_select.rs:466 | `detection_follows_the_d4_order_and_skips_what_is_refused`, `a_profile_command_wins_and_adds_no_default_flag_while_detection_defaults_to_headless` | E2E-41 | OK | |
| S-12 | Launcher seeds `extensions.settings.<id>.incognito=true` into fresh profile before first launch (manifest-key ID) | P10 | A/browser.rs:2987 | `test_launch_seeds_incognito_access_for_the_extension`, `test_committed_manifest_key_gives_the_fixed_extension_id` | E2E-35, E2E-45 | OK | planted-file refusal (a72d78e) covered by the same seeding path; no separate named test found |
| S-13 | Launcher verifies the seeding took effect and fails closed | P10 | A/browser.rs:504 | `test_launch_fails_closed_when_the_extension_is_not_allowed_in_incognito`, `only_an_attached_incognito_allowed_browser_is_intercepting` | E2E-45 | OK | |
| C-01 | `browser_cdp_expose` default `pipe` (fds 3/4), mediation via `browser-control` | pre | A/browser.rs:2679 | `test_build_browser_command_pipe_mode`, `test_create_cdp_pipes` | E2E-01 to 05, 09, 12, 14, 15, 23 to 25, 27, 28, 32, 48, 52 to 54 (pipe mode) | OK | |
| C-02 | Pipe mode: `browser_user` must differ from `principal_user` | pre | A/runtime/gates.rs:37 (call at runtime.rs:982) | `a_pipe_mode_browser_user_must_differ_from_principal_daemon_and_root`, `the_browser_user_rules_apply_only_to_a_root_daemon_in_pipe_mode` | | OK | Closed: refusals for principal, daemon and root uid, and the port-mode and non-root exemptions |
| C-03 | With `browser_scope = session` and `max_concurrent_sessions > 1`, `browser_cdp_port` must be 0 | pre | C/config.rs:1003 | `browser_scope_session_rejects_fixed_port_with_max_gt_1`, `concurrent_port_mode_rejects_fixed_cdp_port`, `browser_scope_profile_accepts_fixed_port_with_max_gt_1` | | OK | Resolved by amending ADR 4.2: the code was right. A fixed port is only unsafe where several browsers could bind it (session scope); profile scope has one shared browser per profile. Nothing was loosened |
| C-04 | `browser-control` unavailable in port mode | pre | A/runtime/gates.rs:69 (call at runtime.rs:2548) | `browser_control_is_refused_for_a_port_mode_lease_only` | | OK | Closed |
| C-05 | Playwright bootstrap: loopback ephemeral port, `GET /json/version` authenticates bearer, runs `EnsureBrowser`, returns real `webSocketDebuggerUrl`, never relays frames | P10 | A/cdp_bootstrap.rs:34 | `discovery_requires_auth_before_side_effects`, `authenticated_discovery_returns_actual_websocket`, `rejects_non_loopback_endpoint`, `health_does_not_start_browser` | E2E-34 | OK | |
| C-06 | Port mode: reduced security, `DevToolsActivePort` removed after discovery | P10 | A/browser.rs:39 | `test_hide_devtools_active_port_removes_the_discovery_file` | E2E-37 | OK | |
| C-07 | A `direct_cdp` caller (Playwright bootstrap, chrome-devtools adapter) is refused for a pipe-mode profile before any browser starts; `agent browser` is served in both modes | pre | A/runtime/gates.rs:85 | `a_direct_cdp_caller_is_refused_in_pipe_mode_only` | E2E-53 (pipe mode, all variants) | OK | The tool error now carries the bootstrap's `503` with the class (`refused`) and a fixed hint, through the error endpoint (C-08) |
| C-08 | `agent mcp playwright` outside a session survives a daemon restart: the client's stdio and the MCP server stay in the wrapper, the session (a broker holding the capability) is re-launched through the admin socket only when lost with its daemon instance, never after the live daemon ended it; no capability, daemon bearer or endpoint is reused; a failed discovery answers through `/passless/unavailable/<class>` | post-P12 | cmd/passless/src/commands/mcp_session.rs | `the_session_is_re_established_after_its_daemon_restarts`, `a_session_the_live_daemon_ended_is_not_re_established`, `a_broker_whose_capability_is_refused_is_replaced_not_reused`, `a_failed_launch_names_the_class_and_leaks_nothing` | E2E-57 | OK | Shared-UID only; chrome-devtools and `agent run` agents still end with the daemon |
| X-01 | MV3 extension is a service worker only: no content script, no MAIN-world override | P6 | cmd/passless/assets/agent-extension/manifest.json:7 | `test_manifest_is_a_worker_only_webauthn_proxy`, `js:942`, `js:997` | E2E-16 | OK | `main.js`/`broker.js` verified absent |
| X-02 | `attach()` on every worker start, idempotent | P6 | worker.js:379 | `js:404`, `js:413` | E2E-18 | OK | |
| X-03 | `onCreateRequest`/`onGetRequest` forwarded verbatim; completed with daemon output verbatim or DOMException name | P6 | worker.js:513 | `js:616`, `js:634`, `js:486` | E2E-16 | OK | |
| X-04 | `onRequestCanceled` sends abort to daemon | P6 | worker.js:513 | `js:710`, `an_abort_before_key_use_signs_nothing_and_is_audited` | E2E-17 | OK | |
| X-05 | Every `onIsUvpaaRequest` answered `false` | P6 | worker.js:513 | `js:731` | | OK | no E2E asserts isUVPAA specifically |
| X-06 | `connectNative` port to `rs.passless.sign_proxy`; length-prefixed JSON frames (hello/request/abort/result/keepalive); worker-allocated multiplexed ids | P6 | A/browser.rs:2347 | `js:587`, `js:598`, `twenty_concurrent_ceremonies_on_one_connection_all_complete`, `an_oversize_frame_length_closes_the_connection_before_any_payload_is_read` | E2E-22 | OK | frame cap 1 MiB T/frame.rs:14, write timeout 5 s T/frame.rs:16 |
| X-07 | Both sides send keepalive at least every 20 s (escalation wait not bound by MV3 limits) | P6 | worker.js:15 | `js:742`, `the_daemon_writes_keepalives_while_the_connection_is_open` | E2E-20 | OK | worker 20 s, daemon 15 s (T/mod.rs:64) |
| X-08 | No HTTP transport | P6 | worker.js (no `fetch`) | `js:942` | | OK | the JS test asserts no `fetch`/`XMLHttpRequest`/`WebSocket` in worker source |
| X-09 | Sign socket `$XDG_RUNTIME_DIR/agent/sign/sock` (0600 in 0700 dir); other browser UID gets `<sign dir>/<uid>/sock` (needs root daemon) | P6 | A/runtime.rs:1212 | `the_socket_is_owner_only_in_an_owner_only_directory`, `a_per_uid_socket_needs_a_root_daemon`, `a_browser_of_another_uid_uses_its_own_socket_or_is_refused_with_the_reason`, `bind_refuses_a_planted_symlink_for_the_sign_directory` | | OK | |
| X-10 | `hello` authenticates bearer and peer; `SO_PEERCRED` UID must equal lease browser UID | P6 | T/mod.rs:592 | `a_hello_from_a_peer_with_another_uid_is_refused_and_audited`, `a_hello_is_accepted_from_the_bound_browser_uid_only`, `hello_with_an_unknown_or_revoked_bearer_is_unauthorized` | | OK | real cross-UID run needs root; deferred to P12 manual |
| X-11 | Native host manifest written only into the lease profile; admits only the committed-key extension ID | P6 | A/browser.rs:2481 | `test_native_messaging_manifest_admits_only_the_fixed_extension_id`, `test_committed_manifest_key_gives_the_fixed_extension_id`, `js:1013` | | OK | `install-native-messaging` removal verified (no symbol left) |

## §5 Identity modes and backend

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| M-01 | same-user clones the constructed human `CredentialBackendHandle`; never reopens human storage path | pre | A/runtime.rs:1270 | `a_same_user_profile_reports_the_human_backends_real_storage_kind` | E2E-01 | OK | "never reopens" is shown by `human_backend.clone()`; no test forbids a reopen |
| M-02 | same-user has no profile storage or PIN path | pre | C/config.rs:1130 | `test_same_user_profile_rejects_storage` | | OK | |
| M-03 | same-user shares human operation lock and counters | pre | A/backend.rs:41 | `concurrent_counter_serialization`, `the_human_operation_lock_is_free_while_a_waiter_is_parked` | E2E-43 | OK | |
| M-04 | same-user may narrow with `credential_refs`; registers into human backend only under explicit registration rule | pre/P3 | A/sign.rs:2010 | `narrow_candidates_pins_before_allow_credentials`, `rule_credential_ref_must_be_in_credential_refs`, `same_user_register_allow_requires_registration_acknowledgement` | E2E-27 | OK | |
| M-05 | isolated: separate storage, key provider, PIN state, lock; cannot enumerate/sign with human | pre | A/storage_factory.rs (bundle) | `test_credential_isolation_between_profiles`, `test_pin_state_isolation_between_profiles`, `test_profiles_do_not_share_arc_mutex` | E2E-02 | OK | |
| M-06 | isolated cannot share a path with the human backend or another profile | pre | C/config.rs:1130 | `test_config_agent_root_overlaps_human_rejected`, `test_storage_cross_profile_credential_overlap_rejected`, `test_config_overlapping_roots_rejected` | | OK | |
| M-07 | No per-profile UHID/hidraw, no daemon CTAP endpoint for agents (inv 24); human UHID unaffected | P3 | (removal) | `test_legacy_device_key_warns_and_is_ignored`, `agent_config_accepts_profiles_sharing_a_legacy_device_identity` | E2E-46 | OK | `endpoint_manager.rs`, `ceremony*.rs`, `device.rs`, `interaction.rs`, `storage.rs` verified deleted; no `endpoint_manager`/`EndpointManager` symbol left |
| M-08 | Sign/register services accept only a runtime-selected handle; never open paths or hardcode the provider | pre | A/backend.rs:24 | `test_getinfo_through_type_erased_service`, `test_separate_type_erased_services_do_not_share_storage` | | OK | |

## §6 Policy

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| P-01 | Schema: `mode`, `principal_user`, `session_ttl`, `max_operations`, `credential_selection`, `rules[]` (`rp_id`, `authenticate`, `register`) | P4 | C/config.rs:226 | `rules_toml_roundtrip_uses_new_vocabulary`, `rule_action_defaults_to_deny_and_roundtrips_lowercase` | E2E-01 | OK | `session_ttl` is an alias of `max_session_ttl` (config.rs:706) |
| P-02 | `deny`: rejected before enumeration/key access; never prompts | P4 | C/resolve.rs:135 | `deny_rule_denies_with_action_not_allowed_and_signs_nothing`, `exact_deny_beats_wildcard_allow` | E2E-03 (pipe mode: E2E-03, E2E-04) | OK | |
| P-03 | `allow`: authorize autonomously; UP/UV from agent-session evidence | P4 | A/sign.rs:1402 | `allow_signs_with_agent_evidence_and_up_uv_flags_even_without_rp_uv_request`, `test_register_allow_sets_up_and_uv_and_audits_agent_evidence` | E2E-01 (pipe mode: E2E-01, E2E-02, E2E-05) | OK | |
| P-04 | `request`: raises an escalation; authenticate approval persists `allow` for the exact RP; register approval permits one registration | P4/P7 | A/escalation.rs:799 | `approved_escalation_persists_the_grant_and_signs_once`, `test_registration_escalation_registers_once_and_persists_a_registration_grant` | E2E-23, E2E-27 (pipe mode: E2E-23, E2E-24, E2E-27) | OK | |
| P-05 | `register` and `authenticate` independent per rule | P4 | C/resolve.rs:126 | `register_actions_resolve_independently_of_authenticate` | E2E-27 (pipe mode: E2E-27) | OK | |
| P-06 | Per-rule `credential_selection` overrides profile value | P4 | C/config.rs:60 | `rule_selection_override_beats_profile_default_for_exact_rule`, `credential_selection_for_rp_uses_exact_rule_override` | E2E-07 | OK | |
| P-07 | Policy owned by operator: principal cannot add, broaden, reload, revoke it or pick evidence at request time | P4 | C/protocol.rs:298 | `admin_request_type_cannot_be_principal_request`, `role_separation_admin_vs_principal`, `test_admin_socket_rejects_principal_frame` | | OK | |
| P-08 | RP IDs normalized exact DNS names: no scheme, port, path, trailing dot, IP, public suffix | P4 | C/config.rs:1813 | `test_rp_id_reject_scheme`, `test_rp_id_reject_port`, `test_rp_id_reject_path`, `test_rp_id_reject_trailing_dot`, `test_rp_id_reject_ipv4`, `test_rp_id_reject_public_suffix` | | OK | |
| P-09 | `localhost` valid for exact rules only; never matches via wildcard | P4 | C/resolve.rs:97 | `localhost_is_a_valid_exact_rp_id_only`, `wildcard_never_governs_localhost`, `wildcard_does_not_resolve_localhost_but_exact_rule_does`, `localhost_signs_through_an_exact_allow_rule` | E2E-06 | OK | |
| R-01 | Resolution: exact deny > exact allow > exact/wildcard request (+exact grant => allow) > wildcard allow > deny | P4 | C/resolve.rs:126 | `exact_deny_beats_wildcard_allow`, `exact_allow_beats_wildcard_deny_and_request`, `exact_request_with_wildcard_allow_is_request`, `granted_request_upgrades_to_allow`, `granted_wildcard_request_upgrades_through_the_exact_grant`, `rule_order_does_not_change_the_outcome` | E2E-12 | OK | |
| R-02 | Granted store can only upgrade `request` to `allow` (never register) | P4/P7 | C/resolve.rs:126 | `grants_never_upgrade_register`, `request_without_grant_stays_request` | E2E-23 (also in pipe mode) | OK | |
| R-03 | Grants made inert when config rule becomes `deny`/is removed | P4 | C/resolve.rs:126 | `orphaned_grants_never_allow_and_are_never_consulted`, `orphaned_grant_is_inert_when_the_rule_is_deny`, `a_grant_is_inert_once_its_rule_is_removed` | | OK | |
| R-04 | `passless doctor` reports inert/orphaned grants as orphaned | P4/P7 | A/doctor_grants.rs:58, runtime.rs:2859 (`profile check`), doctor_agents.rs (`doctor --agents`) | `a_grant_under_a_request_rule_is_live`, `a_grant_under_the_wildcard_request_rule_is_live`, `a_grant_for_an_rp_no_rule_reaches_is_orphaned`, `a_grant_is_inert_when_its_rule_became_deny`, `a_grant_is_redundant_when_its_rule_became_allow`, `only_the_inert_grants_are_reported`, `the_check_warns_without_failing_and_names_each_orphan`, `store_files_of_profiles_that_no_longer_exist_are_reported`, `the_offline_run_reads_the_stores_and_flags_orphans_and_vanished_profiles` | | OK | Closed. A grant is live iff the resolver upgrades it; otherwise it is reported (warning, not a failure) as no rule reaching the RP, rule now `deny`, or rule now `allow`. `doctor --agents` also lists store files of profiles no longer configured |
| W-01 | `*` valid only for same-user, acknowledged in `acknowledge_global_same_user`, `register = "deny"`, no `credential_refs`/`credential:<ref>` | P4 | C/config.rs:1080 | `wildcard_requires_same_user_mode`, `wildcard_requires_global_same_user_acknowledgement`, `wildcard_requires_register_deny_including_request`, `wildcard_forbids_credential_refs`, `wildcard_rule_cannot_use_credential_ref` | E2E-12 | OK | |
| W-02 | Selection under wildcard always `single`; exact rules always take precedence | P4 | C/resolve.rs:126 | `wildcard_forces_single_even_when_the_profile_default_is_newest`, `credential_selection_for_rp_wildcard_is_always_single`, `credential_selection_for_rp_exact_beats_wildcard_and_default` | E2E-07 | OK | |
| W-03 | Every operation resolves through exactly one rule; wildcard match audited `rule = "*"` | P4/P8 | A/operation_audit.rs:360 | `a_wildcard_match_is_audited_as_rule_star`, `a_refused_wildcard_request_is_audited_as_rule_star`, `wildcard_match_reports_wildcard_identity_and_forces_single_selection` | E2E-12 (pipe mode: E2E-12) | OK | |
| V-01 | Unknown fields and enum values fail startup; missing profiles/rules/actions deny | P4 | C/config.rs:272 | `test_config_profile_deny_unknown_fields`, `rule_rejects_unknown_fields`, `test_config_unknown_mode_rejected`, `missing_rule_action_denies` | E2E-13 | OK | |
| V-02 | same-user rejects profile storage/PIN paths; isolated requires complete, non-overlapping backend | P4 | C/config.rs:1130 | `test_same_user_profile_rejects_storage`, `test_profile_isolated_requires_storage`, `test_config_overlapping_roots_rejected` | | OK | |
| V-03 | Same-user registration (`allow`/`request`) requires exact RP and `acknowledge_same_user_registration` | P4 | C/config.rs:1191 | `same_user_registration_requires_operator_acknowledgement`, `same_user_register_request_requires_registration_acknowledgement`, `same_user_register_allow_requires_registration_acknowledgement`, `wildcard_requires_register_deny_including_request` | E2E-27 | OK | |
| V-04 | Legacy evidence tables/presets parse until the release after next (R8) with warning; mapping deny/autonomous/allow+agent+agent/supervised/confirm+*; any other combination fails | P4 | C/config.rs:382 | `legacy_mapping_table_maps_every_row`, `legacy_allow_with_human_or_no_evidence_names_the_evidence`, `legacy_rule_with_both_fields_records_one_warning_per_field`, `config_deprecation_warnings_aggregate_across_profiles` | E2E-13 | OK | Resolved: ADR 6.4, 16, 19 and plan M4 now all say "the release after next (R8)". The code has no removal gate; removal is the R8 release task |
| V-05 | Removed profile fields `rp_ids`, `registration_allowed`, `require_uv`, `human_verification_prompt` fail with migration message | P4 | C/config.rs:802 | `removed_profile_keys_parse_but_fail_validation_with_migration_message`, `removed_profile_keys_are_all_reported_together` | E2E-13 | OK | |
| V-06 | Policy digest covers every rule field, profile `credential_selection`, every acknowledgement; not the grants store | P4/P7 | C/policy.rs:39 | `digest_changes_when_any_policy_field_changes`, `test_digest_covers_escalation_settings_and_grant_cap`, `digest_unchanged_when_rules_are_reordered`, `test_policy_version_constant` | | OK | CURRENT_POLICY_VERSION = 5 matches §19 |
| V-07 | Ceremony resolves against live config + grants, not a frozen copy; revocation epoch vs grant epoch | P5 | A/policy_engine.rs:440 | `test_resolve_is_live_after_reload`, `session_from_before_a_changed_reload_is_revoked`, `an_added_grant_bumps_only_the_grant_epoch`, `reload_reads_a_changed_file_and_bumps_the_revocation_epoch` | E2E-31 | OK | |

## §7 Ceremonies and evidence

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| E-01 | Agent ceremony never invokes notification prompt, PIN path or native WebAuthn; extension never falls back native | P2/P6 | worker.js:513 | `js:835`, `js:942`, `request_rule_without_a_prompt_denies_with_escalation_unavailable_and_signs_nothing` | E2E-09 | OK | |
| E-02 | deny, rejected/timed-out escalation, every policy failure return `NotAllowedError` | P2/P5 | T/webauthn.rs:442 | `wire_codes_and_dom_names_of_transport_errors`, `js:634` | E2E-03, E2E-04, E2E-21 | OK | |
| E-03 | Non-public-key credential calls (passwords, federated) never reach an authenticator | n/a | browser | | E2E-16 | OK | Closed: E2E-16 calls `navigator.credentials.get({password})` and `{federated}` and asserts no policy or operation audit record appears and no notification (not run in this gate: browsers were in use; `node --check` only) |
| E-04 | Invariant 25: proxy routes every create/get to extension; unhandled request fails closed; conditional mediation unavailable while attached | P6/P10 | worker.js:421 | `js:561`, `js:972` | E2E-45 | OK | |
| E-05 | Private `/dev` via `bwrap --dev-bind / / --dev /dev --die-with-parent` whenever bwrap works | P10 | A/containment.rs:397 | `with_bwrap_the_browser_runs_in_the_private_dev`, `test_production_launch_runs_the_browser_under_bwrap` | E2E-46 | OK | |
| E-06 | Launcher refuses to start the browser without private `/dev` when its UID could open any `/dev/hidraw*` | P10 | A/containment.rs:12 | `without_bwrap_an_accessible_hidraw_node_refuses_the_spawn_with_an_actionable_error`, `test_production_launch_is_refused_without_bwrap_when_hidraw_is_accessible` | E2E-46 | OK | `E2E-46/refused` |
| E-07 | `faccessat2(AT_EACCESS, R_OK, W_OK)` over every hidraw node, in the child after credential drop, `/dev` listed by the child, fail closed | P10 | A/containment.rs:15 | `the_hidraw_check_fails_closed`, `the_hidraw_check_sees_only_nodes_this_user_can_read_and_write`, `the_hidraw_check_reads_every_directory_batch` | | OK | |
| E-08 | bwrap probed as the browser's user; bwrap on a path others can write is not used | P10 | A/containment.rs:593 | `bwrap_must_live_on_a_path_nobody_else_can_write`, `a_bwrap_that_cannot_build_the_private_dev_counts_as_unavailable` | | OK | |
| E-09 | Browser forked on a long-lived launcher thread (parent-death signal follows forking thread) | P10 | A/launcher.rs:996 | `a_child_spawned_on_the_launcher_thread_outlives_the_requesting_thread`, `test_b1_browser_outlives_the_request_thread_that_launched_it` | E2E-46 | OK | `E2E-46/session-scope` |
| E-10 | Distinct-UID without hidraw access: containment not required; doctor reports required/defence-in-depth/not-required/refused | P10 | A/containment.rs:593 | `the_case_follows_the_private_dev_and_hidraw_access`, `the_containment_check_fails_only_when_launches_are_refused` | E2E-46 | OK | |
| E-11 | Missing/unloadable extension is a launch error, never a launch without it | P2/P10 | A/browser.rs:2537 | `test_launch_with_missing_extension_is_an_error_and_spawns_nothing`, `test_verify_extension_dir_rejects_unusable_directories`, `test_verify_extension_dir_never_reads_a_planted_device_symlink_or_fifo` | E2E-47 | OK | |
| E-12 | CDP endpoint not handed out until worker attached; withheld again when degraded > 10 s | P6/P10 | A/browser.rs:692 | `test_interception_degrades_after_the_grace_period_and_is_reported_once`, `test_cdp_endpoint_file_exists_only_while_interception_is_attached`, `test_b2_start_url_opens_only_after_the_worker_attached`, `bootstrap_refuses_a_degraded_lease_until_it_re_attaches` | E2E-45 | OK | |
| E-13 | Worker not allowed in incognito counts as not attached (launch fails, endpoint withheld) | P10 | T/readiness.rs:23 | `only_an_attached_incognito_allowed_browser_is_intercepting`, `test_launch_fails_closed_when_the_extension_is_not_allowed_in_incognito` | E2E-45 | OK | `E2E-45/cdp-context` |
| E-14 | Daemon's writes into a lease never follow browser-user-controlled paths (pinned dir handles, `O_EXCL`, `O_NOFOLLOW`, only the profile handed over) | P10 | A/safe_fs.rs:9 | `a_symlink_at_the_leaf_is_refused_and_its_target_untouched`, `a_symlink_at_an_intermediate_component_is_refused_and_its_target_untouched`, `test_cdp_endpoint_rewrite_does_not_follow_a_planted_symlink`, `test_lease_layout_keeps_daemon_written_directories_daemon_owned` | | OK | |
| E-15 | `PASSLESS_INTERACTION_MODE=automatic` never approves an escalation | P7 | A/escalation.rs:799 | `automatic_interaction_mode_does_not_affect_escalation` | E2E-44 | OK | |
| E-16 | Agents refuse to start (and reload is rejected) under automatic mode with same-user `allow`/`request` rule unless `agents.allow_automatic_human_path`; doctor flags it; isolated/deny-only exempt | P10 | C/config.rs:1387 | `automatic_human_path_refuses_same_user_allow_and_request_rules_unless_acknowledged`, `reload_keeps_the_automatic_human_path_guard`, `the_interaction_mode_check_flags_the_automatic_human_path` | E2E-44 | OK | `E2E-44/startup-refusal` |
| E-17 | `allow` sets UP=1/UV=1 only after: bearer active, unexpired, within budget | P5 | A/session.rs:464 | `expired_session_is_denied_before_anything_else`, `budget_is_claimed_only_by_fresh_keys_and_enforced_live`, `validity_tracks_revocation_epoch_and_ttl` | E2E-15 | OK | |
| E-18 | ...session bound to profile, principal digest and browser lease | P5 | A/session.rs:336 | `principal_digest_mismatch_is_denied_and_audited`, `sign_wrong_profile_denied`, `registration_bound_to_a_grant_of_another_principal_is_denied` | | OK | |
| E-19 | ...origin and RP validation passed | P5 | A/sign.rs:211 | `test_origin_verification_denied`, `sign_wrong_rp_denied`, `rejected_requests_never_consume_budget` | E2E-15 | OK | |
| E-20 | ...revocation epoch unchanged and rule re-resolved to `allow` immediately before key use (inv 13) | P5 | A/sign.rs:1870 | `changed_reload_revokes_an_in_flight_operation_before_key_use`, `reload_to_deny_is_enforced_by_the_unchanged_handler` | E2E-31 | OK | |
| E-21 | ...replay key fresh; durable audit reservation succeeded | P5/P8 | A/session.rs:499 | `fresh_claim_consumes_one_operation_and_duplicates_none`, `audit_pre_write_blocks_sign` | E2E-14 | OK | |
| E-22 | Audit always labels evidence `agent`; rules carry no evidence fields; RP `userVerification` never sets UV | P4/P8 | A/sign.rs:1402 | `test_register_user_verification_request_is_irrelevant_under_allow`, `allow_sets_up_and_uv_when_the_rp_requests_uv_too`, `test_operation_record_values` | E2E-01 | OK | |
| E-23 | `credProtect` evaluated against agent evidence (level 3 satisfied only because operator chose `allow`) | pre | A/cred_protect.rs:20 (call at sign.rs:1856) | `level_one_and_no_level_never_need_uv`, `level_two_needs_uv_unless_the_request_names_the_credential`, `level_three_needs_uv_with_or_without_allow_credentials`, `an_unknown_level_is_as_strict_as_level_three`, `agent_evidence_satisfies_every_level_with_or_without_allow_credentials` | | OK | Closed. Level 2 is implemented (UV unless `allowCredentials` names the credential; unreachable with agent UV = true, kept for invariant 15). Agent registration creates credentials without a level; the check protects credentials created elsewhere |

## §8 Escalation and granted rules

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| F-01 | `request` creates/joins pending escalation keyed `(profile, rp_id, action)`; concurrent authenticate join; registration not joinable | P7 | A/escalation.rs:799 | `authenticate_escalations_join_and_coalesce_into_one_prompt`, `registration_is_not_joinable_and_its_approval_is_a_token` | E2E-25 | OK | |
| F-02 | `escalation_requested` audit record; failed write fails the ceremony | P7/P8 | A/audit_events.rs:123 | `audit_failures_fail_the_escalation`, `escalation_requested_names_the_rule_and_origin` | E2E-32 | OK | |
| F-03 | Notification built only from daemon-derived fields; only actions **Allow always** and **Deny** | P7 | A/escalation_prompt.rs:261 | `render_uses_daemon_fields_and_punycode`, `render_strips_line_breaks_markup_and_bidi_controls`, `driver_shows_daemon_fields_only_with_the_fixed_actions`, `request_validation_pins_the_action_set` | E2E-28 | OK | |
| F-04 | Call stays open until decision or effective timeout; parked waiter holds no lock and no request-cap slot | P7 | A/escalation.rs:799 | `the_human_operation_lock_is_free_while_a_waiter_is_parked`, `a_duplicate_joined_to_a_parked_original_holds_no_request_slot`, `wait_suspends_and_resumes_the_park_hook` | E2E-20 | OK | |
| F-05 | Timeout = page `timeout` clamped 3 min to 20 h, 20 h when unset; optional shorter `agents.escalation_timeout` | P7 | C/config.rs:33 | `the_transport_deadline_follows_chromiums_clamp`, `ceremony_deadline_is_clamped`, `escalation_cooldown_and_timeout_are_bounded` | E2E-21 | OK | |
| F-06 | Notification has no expiry; withdrawn when ceremony ends/aborts/times out | P7 | A/escalation_prompt.rs:16 | `withdraw_and_eof_send_close_notification`, `last_waiter_timing_out_expires_with_cooldown_and_withdraws_the_prompt` | E2E-28, E2E-21 | OK | `expire_timeout = 0` |
| F-07 | Approval: write `escalation_approved`, persist grant atomically, bump grant epoch, re-resolve, continue as `allow` | P7 | A/escalation.rs:799 | `approved_escalation_persists_the_grant_and_signs_once`, `the_grant_is_audited_before_the_store_write_and_an_audit_failure_denies`, `store_failures_turn_the_approval_into_a_deny` | E2E-23 | OK | |
| F-08 | Denial/timeout: `escalation_denied`/`escalation_expired`, cooldown for the key (default 10 min) | P7 | C/config.rs:28 | `deny_starts_the_cooldown_until_the_clock_passes_it`, `escalation_keys_have_defaults_and_parse` | E2E-24 | OK | |
| F-09 | Aborted waiter stops waiting; last waiter gone: withdrawn, notification closed, late click ignored, `expired(reason=aborted)` | P7 | A/escalation.rs:87 | `stale_or_late_tickets_are_ignored`, `an_abort_close_to_the_deadline_counts_as_a_timeout`, `an_invalid_session_leaves_the_wait` | E2E-19, E2E-50 | OK | `reason=aborted` audit asserted in E2E-32/abort |
| F-10 | 3 withdrawals per key within 10 min start the cooldown (V-M2) | P7 | A/escalation.rs:78 | `third_withdrawal_within_ten_minutes_starts_the_cooldown`, `withdrawals_outside_the_window_do_not_add_up` | E2E-50 | OK | |
| F-11 | Queued entry dequeued when last waiter leaves; active prompt with zero waiters withdrawn immediately | P7 | A/escalation.rs:70 | `queue_is_fifo_bounded_and_dequeues_on_last_waiter`, `active_prompt_with_zero_waiters_is_withdrawn_and_the_next_shown` | E2E-26 | OK | |
| H-01 | Approval only from the notification server's verified D-Bus sender (zbus `ActionInvoked`); no API/CLI/extension message approves | P7 | A/escalation_prompt.rs:524 | `child_ignores_a_spoofed_sender`, `child_subscribes_before_notify` | E2E-29 | OK | the "no API/CLI approves" half is shown by the admin/principal enums having no approve variant (checked by reading); no dedicated negative test |
| H-02 | Capability gate fails closed on servers without distinct actions; `min_review_delay_ms` is a heuristic | P7 | A/escalation_prompt.rs:13 | `capability_gate_rejects_servers_without_actions`, `single_action_servers_are_rejected`, `child_denies_an_approval_before_its_review_delay` | E2E-42 | OK | |
| H-03 | `agents.notify_user` names the bus owner; no bus means immediate deny, audited (`escalation_unavailable`) | P7 | C/config.rs:1201 | `root_daemon_without_a_usable_notify_user_has_no_escalation`, `prompt_failure_denies_as_unavailable_without_cooldown`, `non_root_daemon_may_only_notify_its_own_user` | E2E-30, E2E-09 | OK | |
| H-04 | Root daemon uses a per-prompt child that drops privileges (setgroups, setresgid, setresuid, NO_NEW_PRIVS, no caps) and connects to `unix:path=/run/user/<uid>/bus` first; daemon never changes credentials | P7 | A/launcher.rs:790 | `root_daemon_drops_to_notify_user_on_its_bus`, `process_child_has_a_scrubbed_environment_no_new_privs_and_no_inherited_fds`, `the_planned_identity_passes_the_hardened_setup_checks`, `reexecuted_binary_runs_the_prompt_child_with_only_the_bus_address`, `driver_fails_a_silent_child_and_kills_a_withdrawn_one` | | OK | "no capabilities" follows from `setresuid` away from root (no explicit capset). Real-root run not performed (P0a note) |
| H-05 | One prompt per profile at a time; other keys queue in a bounded queue; overflow denied | P7 | A/escalation.rs:70 | `queue_is_fifo_bounded_and_dequeues_on_last_waiter` | E2E-26 | OK | E2E-26 does not exercise the bound (plan documents this; unit-covered) |
| H-06 | Waiters: 4 per session, 16 per profile, 64 total; beyond cap denied and audited; other profiles unaffected | P7 | A/escalation.rs:72 | `waiter_caps_per_session_profile_and_global`, `each_cap_rejects_with_its_scope_and_permits_release_every_slot`, `one_profile_saturating_its_cap_leaves_room_for_another_profile` | E2E-48 | OK | |
| H-07 | Budget claimed only after origin/policy validation and, for `request`, after approval | P5/P7 | A/session.rs:499 | `no_budget_is_claimed_unless_the_escalation_is_approved`, `a_key_only_claim_takes_budget_only_when_claimed_and_refunds_only_that` | E2E-15 | OK | |
| H-08 | Distinct-UID: `notify_user` must differ from every `principal_user` and `browser_user`; same-UID self-approval is residual | P7/P11 | C/config.rs:1436 | `root_daemon_notify_user_must_differ_from_principal_and_browser_users`, `escalation_check_reports_an_unusable_notify_user` | | OK | residual risk documented in `docs/agents/{rules,containment,security}.md` |
| RG-01 | `register = "allow"` never obtained via escalation; `register = "request"` valid only where `allow` would be, invalid with `authenticate = "deny"` | P4 | C/config.rs:1047 | `register_request_rejected_with_authenticate_deny`, `register_request_accepted_on_exact_rp_with_authenticate_allow_or_request`, `register_request_rejected_on_wildcard` | E2E-27 | OK | |
| RG-02 | Registration escalations not joinable; concurrent duplicate for same `(profile, rp_id)` denied | P7 | A/escalation.rs:231 | `test_concurrent_registration_escalation_is_busy_not_joined`, `registration_is_not_joinable_and_its_approval_is_a_token` | | OK | |
| RG-03 | Approval is a one-use token bound to the creating ceremony; exactly one registration for that RP | P7 | A/escalation.rs:231 | `test_registration_request_needs_its_own_approval_before_key_use`, `a_registration_approval_cancelled_while_deciding_stands_cancelled` | E2E-27 | OK | |
| RG-04 | Does not persist `register = allow`; on success persists `authenticate = allow`, `kind = registration`, credential ref; ref joins pinned set | P7 | A/register.rs:587 | `test_registration_escalation_registers_once_and_persists_a_registration_grant`, `registration_grant_credentials_join_the_configured_pins` | E2E-27 | OK | |
| RG-05 | If registration fails after approval nothing is persisted | P7 | A/register.rs:587 | `a_registration_that_fails_after_approval_persists_nothing`, `test_failed_registration_grant_write_keeps_the_credential` | | OK | Closed: approval then a reload before key use leaves no credential and no grant, and `authenticate` still escalates |
| GS-01 | Store at `<state_dir>/granted-rules/<profile>.toml`, 0600 in 0700; default `$XDG_STATE_HOME/passless/agent` (user), `/var/lib/passless-agent` (system) | P7 | C/config.rs:1351 | `round_trip_persists_with_owner_only_modes`, `store_directory_must_be_owner_only`, `effective_state_dir_prefers_the_configured_one`, `the_state_directory_is_systemd_managed_and_matches_the_tmpfiles_entry` | E2E-31 | OK | Resolved in code: the system unit now has `StateDirectory=passless-agent` and `StateDirectoryMode=0700` (systemd's default 0755 would widen the directory), compatible with the root:root 0700 tmpfiles entry; the ADR text was already right |
| GS-02 | Daemon never writes the operator's config file | P7 | (absence) | `the_daemon_never_writes_the_operator_config` | | OK | Closed: add, revoke, clear, revoke_request and a policy reload leave the config's bytes and (pre-aged) mtime unchanged and add nothing next to it |
| GS-03 | Entry fields: `rp_id`, `action`, `kind`, `granted_at`, `request_id`, origin, permitting rule | P7 | A/granted_rules.rs:233 | `round_trip_persists_with_owner_only_modes`, `rfc3339_formats_utc_seconds` | E2E-27 | OK | |
| GS-04 | Write = temp file, fsync, rename, fsync dir; failed write fails approval and denies | P7 | A/granted_rules.rs:8 | `leftover_tmp_file_is_ignored_and_replaced`, `store_failures_turn_the_approval_into_a_deny` | | OK | |
| GS-05 | Read at startup and after each write; malformed/wrongly owned store disables grants (fail closed), doctor reports | P7 | A/granted_rules.rs:233 | `corrupt_store_disables_grants`, `wrong_owner_disables_grants`, `group_readable_store_disables_grants`, `symlinked_store_disables_grants`, `granted_rules_check_fails_for_a_disabled_store` | E2E-31 | OK | |
| GS-06 | Store has its own `grants_digest` reported next to the policy digest | P7 | A/granted_rules.rs:471 | `the_grants_digest_is_stable_for_the_same_set_and_changes_on_add_and_revoke`, `the_grants_digest_is_not_the_policy_digest_and_the_policy_digest_ignores_grants` | | OK | Closed; reported at runtime.rs:2984 and :3098 |
| GS-07 | Admin: `agent-admin grants list [--profile]`, `revoke --profile --rp [--action] --confirm`, `clear --profile --confirm`; revocation audited `granted_rule.revoke`; hidden aliases `delegation`, `session` | P7 | C/config.rs:991 | `test_agent_admin_grants_parse`, `test_agent_admin_renamed_session_commands_keep_hidden_aliases`, `revoke_and_clear_bump_the_revocation_epoch_and_revoke_sessions`, `admin_granted_rule_requests_roundtrip` | E2E-31 | OK | audit kind A/audit_events.rs:157 |
| GS-08 | Lifetime permanent until revoked or inert; no TTL | P7 | A/granted_rules.rs:233 | `preseeded_store_upgrades_request_to_allow_through_resolve` | E2E-23 | OK | |
| GS-09 | Add bumps grant epoch without revoking sessions; revoke/reload/config change bumps revocation epoch (global) and invalidates sessions | P7 | A/policy_engine.rs:452 | `add_bumps_only_the_grant_epoch`, `revoke_and_clear_bump_the_revocation_epoch_and_revoke_sessions`, `a_grants_clear_cancels_the_waiting_escalation` | E2E-31 | OK | |
| GS-10 | `LOCKING.md` normative lock order; no wait holds a lock | P7 | A/lock_order.rs:13 | `sign_path_follows_the_lock_order`, `sign_path_with_the_real_lease_activation_follows_the_lock_order` | | OK | |
| GS-11 | `max_granted_rules` default 64; above it requests denied | P7 | C/config.rs:24 | `grant_cap_and_disabled_store_deny_before_any_prompt`, `max_granted_rules_is_bounded`, `add_rejects_wildcard_and_invalid_rp_ids_and_the_cap` | | OK | |

## §9 Sessions and replay

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| SE-01 | Bearer session binding: profile, mode, principal digest, lease, revocation epoch at creation, TTL, `max_operations` | P5 | A/session.rs:336 | `validity_tracks_revocation_epoch_and_ttl`, `principal_digest_mismatch_is_denied_and_audited`, `budget_limit_is_read_from_the_live_policy` | | OK | |
| SE-02 | Daemon enforces configured maxima for TTL and `max_operations` | P5 | C/config.rs:38 | `test_policy_validation_excessive_ttl`, `test_session_grant_ttl_is_bounded_by_max_session_ttl_not_max_grant_ttl`, `max_granted_rules_is_bounded` | | OK | |
| SE-03 | Self-issued session within policy; session (grant) request and approval audited | pre | A/grant.rs:495 | `test_grant_request_and_approve_emit_audit_records` | E2E-32 | OK | |
| SE-04 | Order of checks (allow: replay, budget, audit; request: cooldown, cap, bus, queue, replay, wait, budget, audit; then epoch re-check, re-resolve, key use) | P5/P7 | A/sign.rs:1287 | `rejected_requests_never_consume_budget`, `failures_before_key_use_never_exhaust_the_budget`, `a_replay_duplicate_joins_the_pending_escalation`, `grant_cap_and_disabled_store_deny_before_any_prompt` | E2E-15 | OK | |
| SE-05 | Bearer validated against revocation epoch on every request | P5/P6 | T/mod.rs:58 | `every_request_revalidates_the_bearer`, `a_revocation_epoch_change_refuses_the_next_request` | | OK | |
| SE-06 | Replay key `SHA-256(action ‖ rp_id ‖ origin ‖ top_origin ‖ challenge)`, per session until expiry | P5 | A/session.rs:82 | `replay_key_encoding_is_unambiguous`, `an_origin_spelled_differently_with_the_same_challenge_is_rejected` | E2E-14 | OK | |
| SE-07 | Identical key never signs/creates twice; in-flight duplicate joins until deadline; duplicate's abort detaches only it | P5 | A/session.rs:235 | `in_flight_duplicate_joins_and_is_never_signed_twice`, `a_detached_duplicate_does_not_affect_the_original`, `identical_registration_creates_one_credential_and_returns_the_same_result`, `join_returns_the_original_outcome_and_a_detached_duplicate_leaves_it_running` | E2E-14 | OK | |
| SE-08 | After completion duplicate gets original result for 120 s, same session only; any other repeat rejected; failures consume the key | P5 | A/session.rs:36 | `completed_duplicate_gets_the_original_result_and_is_never_signed_twice`, `completed_outcome_expires_into_a_rejection`, `a_failure_consumes_the_key_and_is_returned_to_the_duplicate`, `a_completed_duplicate_is_not_served_to_a_revoked_session`, `same_challenge_with_another_rp_or_action_is_rejected_not_joined` | E2E-14 | OK | |
| SE-09 | Revocation (browser exit, lease revocation, principal death, TTL, reload, grant revocation) revokes sign and registration bearers; no separate registration grant | P3/P5 | A/sign.rs (registry) | `test_registry_revoke_by_lease`, `revoke_by_lease_revokes_registration_bearers_only_for_that_lease`, `registration_after_lease_revocation_is_refused_and_audited`, `unbound_registration_bearer_is_unusable`, `test_e2e_registration_bearer_revoked_with_lease` | E2E-11, E2E-31 | OK | |
| SE-10 | In-flight op whose session/generation is invalid fails before key use; additive grant is not a change | P5/P7 | A/sign.rs:1870 | `request_in_flight_when_the_lease_is_revoked_creates_no_credential`, `changed_reload_revokes_an_in_flight_operation_before_key_use`, `an_added_grant_bumps_only_the_grant_epoch` | | OK | |

## §10 Selection, operation service, registration

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| SL-01 | `credential:<ref>`/`credential_refs` narrow first; non-empty `allowCredentials` chooses within the pinned set; exactly one left => use it | P4 | A/sign.rs:2010 | `narrow_candidates_pins_before_allow_credentials`, `pinned_credential_wins_over_allow_credentials`, `allow_credentials_chooses_within_the_set_and_beats_single` | E2E-05, E2E-07 | OK | |
| SL-02 | `single` default (exactly one candidate), `first-matching` (stable by credential ID), `newest`, `credential:<ref>` | P4 | A/sign.rs:2024 | `select_credential_follows_the_selection_rules`, `exact_rule_applies_profile_selection_newest_and_first_matching` | E2E-07 | OK | |
| SL-03 | With no applicable policy, fail with a selection error rather than pick an arbitrary account | P4 | A/sign.rs:2024 | `first_allow_credentials_entry_no_longer_wins_with_several_candidates`, `select_credential_follows_the_selection_rules` | E2E-07 | OK | |
| SL-04 | Selector precedence: exact-rule override, wildcard (single), profile default | P4 | C/config.rs:60 | `credential_selection_for_rp_exact_beats_wildcard_and_default`, `credential_selection_for_rp_unmatched_rp_uses_profile_default` | E2E-07 | OK | |
| SL-05 | Discovery happens in the daemon; page/agent never get an unrestricted listing | pre | C/protocol.rs:455 | `json_envelope_credential_list_no_secrets` | | OK | |
| OS-01 | One operation service: mode-selected backend, RP options, backend capabilities, algorithms, operation lock, provider sign/generate, atomic counter update, audit finalize, WebAuthn response or DOMException | P5 | A/sign.rs:1287 | `sign_allow_and_verify`, `ipc_dispatch_uses_same_sign_core_as_delegation`, `get_response_json_has_the_webauthn_shape`, `create_response_json_has_the_webauthn_shape_and_its_spki_verifies_a_later_assertion` | E2E-01 | OK | |
| OS-02 | Per-credential lock spans read-sign-update; human and agent paths cannot race a counter (inv 17) | pre | A/sign.rs:1870 | `concurrent_counter_serialization`, `test_register_concurrent_requests_serialized`, `monotonic_sequential_counter` | E2E-43 | OK | |
| OS-03 | Authentication honors `allowCredentials`, discoverable creds, user handles, counters, supported extensions | P5 | A/sign.rs:932 | `sign_wrong_allow_credentials_denied`, `persisted_counter_visible_after_reconstruct`, `unsupported_extension_is_not_supported_and_claims_no_budget` | E2E-05 | OK | |
| OS-04 | Daemon builds `clientDataJSON` `webauthn.get`/`webauthn.create` | P6 | A/sign.rs:108 | `test_client_data_json_with_cross_origin`, `test_build_client_data_json_for_registration_with_cross_origin`, `the_daemon_builds_client_data_and_the_frame_cannot_change_it` | E2E-01 | OK | |
| OS-05 | `remoteDesktopClientOverride` is browser metadata, not an unsupported extension | P6 | T/webauthn.rs:6 | `unsupported_extensions_are_not_supported_but_the_browser_override_is_not_one` | | OK | |
| RE-01 | Registration targets the mode's backend (same-user human, isolated profile) | P3 | A/register.rs:223 | `test_register_writes_credential`, `test_e2e_registration_via_extension` | E2E-02, E2E-27 | OK | |
| RE-02 | Denied unless exact rule says `allow` (or escalation approves) | P3/P7 | A/register.rs:223 | `test_register_rejects_denied_policy`, `test_register_unlisted_rp_is_denied_and_audited`, `test_register_under_wildcard_is_always_denied`, `test_exact_rule_wins_over_wildcard_for_registration` | E2E-11 | OK | |
| RE-03 | Honors `pubKeyCredParams` in RP order, `excludeCredentials` (match rejects), UV/authenticator-selection constraints | P5 | A/register.rs:243 | `test_register_exclude_list_match`, `test_unsupported_algorithm_is_a_deny_not_an_allow`, `a_platform_attachment_is_not_supported_but_cross_platform_is_fine`, `test_e2e_registration_exclude_list` | | OK | RP-order preference is not asserted by a named test |
| RE-04 | Key via `CredentialKeyProvider::generate()` (TPM generate+seal in one step), random credential ID | pre/P5 | A/register.rs:737 | `test_register_generates_keypair`, `test_generate_credential_id_unique`, `test_e2e_registration_with_tpm` | | OK | |
| RE-05 | `authenticatorData` with attested credential data, attestation `none`; credential written before returning | P5 | A/register.rs:1000 | `test_register_attested_credential_data_round_trips_and_verifies`, `test_build_attestation_object_is_valid_cbor`, `test_register_success_response_fields` | E2E-02 | OK | |
| RE-06 | Unsupported requirements (enterprise attestation, extensions, platform attachment, no common algorithm) return `NotSupportedError` before storage mutation; `residentKey` is accepted | P5 | T/webauthn.rs:150 | `unsupported_extension_is_not_supported_and_claims_no_budget`, `a_platform_attachment_is_not_supported_but_cross_platform_is_fine` | | OK | Resolved by amending ADR 10.3: `residentKey` and `requireResidentKey` are accepted at every value because every agent credential is discoverable, so refusing one would deny a request the credential already satisfies |
| RE-07 | Same-user `allow` needs only exact RP rule + acknowledgement; no operator-minted enrollment grant or CLI | P3 | A/register.rs:223 | `test_register_allow_needs_no_enrollment_grant`, `same_user_register_allow_requires_registration_acknowledgement` | E2E-11 | OK | `request_registration_grant`, `RegistrationGrantRegistry`, `RequestRegistration` verified absent |

## §11 Browser extension contract

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| B-01 | Attach on every start; listeners registered synchronously at top level (stopped worker woken) | P6 | worker.js:513 | `js:972`, `js:404` | E2E-18 | OK | |
| B-02 | Extension never constructs/edits `clientDataJSON` or any response part | P6 | worker.js:513 | `js:616`, `the_daemon_builds_client_data_and_the_frame_cannot_change_it` | E2E-16 | OK | |
| B-03 | Abort propagates to daemon, which cancels any pending escalation wait; honors RP timeout and browser shutdown | P6/P7 | A/escalation.rs:87 | `js:710`, `a_reload_cancels_the_waiter`, `eof_cancels_every_in_flight_request`, `js:486` | E2E-19, E2E-17 | OK | |
| B-04 | Return correct DOMException names | P5/P6 | T/webauthn.rs:442 | `js:634`, `wire_codes_and_dom_names_of_transport_errors` | | OK | |
| B-05 | Track in-flight by browser request ID; pending ids in `chrome.storage.session`; fail with `NotAllowedError` on worker restart | P6 | worker.js:120 | `js:878`, `js:892`, `js:927` | E2E-19 | OK | |
| B-06 | Never call `chrome.runtime.reload()` | P6 | worker.js (absent) | `js:942` | | OK | |
| B-07 | Origin only from browser-supplied `remoteDesktopClientOverride.origin`; daemon re-parses request details itself | P6 | T/webauthn.rs:213 | `js:523`, `js:533`, `the_daemon_builds_client_data_and_the_frame_cannot_change_it`, `ceremony_audit_records_carry_the_origin_context` | E2E-10 | OK | |
| B-08 | `sameOriginWithAncestors = false` denied; audit `top_origin = null` with `cross_origin` | P2/P6 | A/sign.rs:1477 | `cross_origin_request_is_denied_and_audited`, `cross_origin_is_denied_even_without_a_top_origin`, `a_cross_origin_request_is_denied_and_audited_without_a_top_origin`, `test_cross_origin_always_fails_closed` | E2E-10 | OK | |
| B-09 | Daemon does own origin/RP check as defence in depth; does not rely on suffix rule (related origins); explicit ports valid | P5/P6 | A/sign.rs:211 | `test_origin_verification_accepts_rp_subdomain_origin`, `test_origin_verification_accepts_port`, `test_register_explicit_https_port_allowed` | | OK | |
| B-10 | Conditional mediation: `get()` rejected, `isConditionalMediationAvailable()` false while attached | P6 | worker.js:421 | `js:561` | E2E-45 | OK | |
| B-11 | Worker lifecycle: attachment persists across worker stops; a request wakes the worker | P6 | worker.js:379 | `js:404` | E2E-18, E2E-45 | OK | |
| B-12 | Known limitation: `create()` from an unfocused tab; audit records registration; operator deletes orphan | P6/P11 | (documented limitation) | | E2E-51 | OK | `agent-admin credential delete` fixed in P6; adapters do not raise tabs (§19 "Not done") |

## §12 Audit

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| A-01 | Audit mandatory; durable fsynced reservation before any creation/use; failure blocks key use; terminal record follows every reservation | pre/P8 | A/audit.rs:1278 | `audit_pre_write_blocks_sign`, `test_fsync_failure`, `a_successful_sign_is_one_reservation_and_one_terminal_record_with_every_field`, `a_successful_registration_is_one_reservation_and_one_terminal_record` | E2E-32 | OK | |
| A-02 | Owner-only, append-oriented, hash-chained storage | pre | A/audit.rs:682 | `test_audit_gate_hash_chain`, `test_audit_gate_rejects_wrong_mode`, `test_audit_gate_detects_tampering` | | OK | |
| A-03 | Terminal write failure puts agent support into degraded state; human path unaffected | pre/P8 | A/audit.rs:553 | `test_circuit_breaker_permanent`, `a_durable_but_unacknowledged_reservation_blocks_key_use_and_is_closed_at_restart` | | OK | |
| A-04 | Records never contain keys, PINs, capabilities, bearers, cookies, tokens, raw assertions, client-data hashes, credential records | pre | A/audit_events.rs | `test_no_forbidden_field_names_in_any_event`, `test_no_forbidden_key_substrings_in_any_event`, `test_no_secret_value_patterns`, `test_no_raw_byte_arrays_in_any_event` | E2E-32 | OK | |
| A-05 | Operation record carries the §12 field set (schema v3, keys always present, null when n/a) | P8 | A/audit_events.rs:33 | `test_every_operation_record_carries_exactly_the_canonical_section_12_fields`, `test_section_12_field_list_has_no_duplicates`, `test_schema_version_is_bumped_for_the_section_12_records` | E2E-32 (also in pipe mode) | OK | `AUDIT_SCHEMA_VERSION = 3` |
| A-06 | Reservation and terminal share `request_id`; exactly one `operation.terminal` per `policy.allow` on every path; drop guard writes `abandoned` | P8 | A/operation_audit.rs:360 | `a_ceremony_that_panics_still_gets_its_terminal_record`, `a_panic_in_key_generation_still_gets_exactly_one_abandoned_terminal_record`, `an_abort_after_the_reservation_ends_in_an_aborted_terminal_record`, `a_revocation_before_key_use_ends_in_a_revoked_terminal_record` | E2E-32 (also in pipe mode) | OK | |
| A-07 | `result` in {success, replay_served, denied, aborted, revoked, timeout, busy, error} | P8 | A/audit_events.rs:1071 | `test_failure_classes_map_to_results`, `test_operation_record_values` | E2E-32 (also in pipe mode) | OK | |
| A-08 | Killed daemon: next start closes open reservations in the newest two segments with `error`/`abandoned` | P8 | A/operation_audit.rs:381 | `a_reservation_left_open_by_a_dead_daemon_is_closed_at_the_next_start`, `recovery_scans_only_the_newest_segments` | | OK | called from runtime.rs:940 |
| A-09 | Durable but unacknowledged reservation: `DurableUnacknowledged`, circuit broken, recovered at restart | P8 | A/audit.rs:80 | `a_durable_but_unacknowledged_reservation_stays_open_and_is_recovered`, `a_durable_but_unacknowledged_reservation_blocks_key_use_and_is_closed_at_restart` | | OK | |
| A-10 | Duplicate whose deadline passes is `policy.deny` with `failure_class = join_timeout`, `result = timeout` | P8 | A/sign.rs:1014 | `a_duplicate_whose_deadline_passes_while_it_waits_is_audited_as_a_join_timeout` | | OK | |
| A-11 | Transport-level busy refusals write no operation record | P5/P8 | T/mod.rs:169 | `requests_over_the_connection_cap_get_an_explicit_busy_and_none_is_dropped`, `connections_over_the_connection_cap_are_answered_busy` | E2E-22 | OK | Closed: both tests now assert the audit holds no `policy.deny`, no extra reservation or terminal record and no `result = busy` |
| A-12 | Session grant request/approve (profile, principal, RP scope, TTL), escalation requested/approved/denied/expired/revoked, lease create/expire/revoke/exit/cleanup recorded | P8 | A/runtime.rs:217 | `test_escalation_session_grant_and_lease_records_carry_exactly_their_listed_fields`, `a_launched_lease_is_audited_once_with_its_profile_and_cdp_mode`, `closing_a_lease_audits_one_revoke_with_its_reason_and_one_cleanup`, `a_crashed_lease_is_audited_once_with_its_exit_code_then_cleaned_up`, `an_expired_lease_is_audited_once_then_cleaned_up_even_when_only_the_manager_holds_it` | E2E-32 | OK | |
| A-13 | Escalation timeout/abort = `expired` with `reason = timeout` or `aborted`; `server_lost` expires without cooldown; `revoked(reason = policy_reload)` only when policy changes under a pending escalation | P7/P8 | A/audit_events.rs:123 | `test_escalation_reason_codes_serialize_stably`, `server_lost_expires_without_cooldown_but_counts_for_v_m2` | E2E-21, E2E-49 | OK | Resolved by amending ADR 12 to list `expired(reason = server_lost)` and `revoked(reason = policy_reload)` |

## §13 Deployment axes and hardening

| ID | Decision | Ph | Code | Unit/JS tests | E2E | St | Note |
|---|---|---|---|---|---|---|---|
| DA-01 | Relationship derived from principal UID vs daemon UID; doctor and every audit record report both axes | P9 | A/deployment.rs:18 | `the_relationship_is_the_principal_uid_against_the_daemon_uid`, `audit_and_doctor_report_the_same_axes_for_every_combination`, `the_audit_strings_are_stable` | E2E-33 | OK | |
| DA-02 | shared-UID `isolated`: startup warns separation is administrative only | P9 | A/deployment.rs:130 | `isolated_shared_uid_warns_that_separation_is_administrative_only`, `only_the_isolated_shared_uid_cell_warns`, `test_same_uid_is_reported_and_not_fatal` | E2E-33 | OK | |
| DA-03 | Shared-UID spawn: close-on-exec descriptors, `PR_SET_PDEATHSIG` from launcher thread, no NO_NEW_PRIVS in port-mode spawn, rlimits optional | P10 | A/launcher.rs:996 | `a_same_user_hardened_child_inherits_no_daemon_descriptor`, `hardened_child_arms_the_parent_death_signal_and_checks_the_parent`, `cloexec_except_keeps_only_the_preserved_descriptors_across_exec` | E2E-46 | OK | |
| DA-04 | Distinct-UID: root unit; never changes own credentials for the bus; `notify_user` differs from principal/browser users | P7/P9 | A/prompt.rs:811 | `root_daemon_drops_to_notify_user_on_its_bus`, `test_principal_root_is_still_fatal`, `a_root_daemon_refuses_a_principal_with_its_uid_or_root` | | OK | |
| DA-05 | Other-user browser rlimits: no address-space limit, 4096 processes, 8192 fds, no core dumps | P10 | A/browser.rs:61 | `test_browser_hardening_rlimits_fit_chromium` | | OK | |
| DA-06 | Systemd baseline enabled: ProtectHostname, ProtectClock, ProtectKernelLogs, LockPersonality, RestrictRealtime, ProtectKernelTunables, ProtectControlGroups, ProtectKernelModules, RestrictSUIDSGID; `NoNewPrivileges=false` | pre | contrib/systemd/passless-agent.service:73 | `the_unit_enables_every_baseline_directive_of_the_adr`, `the_unit_keeps_the_root_launch_model_the_baseline_is_designed_around` (`cmd/passless/tests/systemd_unit_baseline.rs`) | | OK | Closed: the unit file is parsed and the nine directives, `NoNewPrivileges=false`, no `User=`/`Group=` and the deferred directives' absence are asserted |
| DA-07 | "To evaluate" directives, namespaces, seccomp | n/a | (not implemented) | | | OK | explicitly open backlog in ADR §13/§19; not a decision to implement |

## §14 Security invariants (full list, evidence is the ID of the item above)

| Inv | Statement (short) | Evidence items | St |
|---|---|---|---|
| 1 | Agent support disabled by default | G-01 | OK |
| 2 | Every profile has exactly one identity mode | `test_config_unknown_mode_rejected`, `test_agent_mode_serde_isolated` (C/config.rs:119); omitted-mode behaviour not separately tested | OK |
| 3 | Same-user uses human handle, never reopens path | M-01 | OK |
| 4 | Isolated cannot obtain human handle | M-05, M-06 | OK |
| 5 | Storage, key provider, verification, lock selected as one unit | M-08 | OK |
| 6 | No keys/PINs/handles/signing API to extension, page, agent | G-03, D-01 | OK |
| 7 | No human interaction or native fallback | E-01, E-04 | OK |
| 8 | UP/UV only from validated agent evidence under `allow` | E-17 to E-22 | OK |
| 9 | One rule per operation; exact > granted > wildcard | R-01, W-03 | OK |
| 10 | Only explicit `request` can escalate; `deny`/unlisted never prompt | P-02, `unmatched_rp_denies_with_action_not_allowed`, E2E-03, E2E-04 | OK |
| 11 | Escalations approved only via verified notification sender | H-01, E-15 | OK |
| 12 | Granted rules exact-RP, additive, atomic, in digest, revocable | R-02, GS-04, GS-07; "in digest" is the store's own `grants_digest` (ADR 8.4: the policy digest excludes grants), GS-06 | OK |
| 13 | Revocation epoch + resolved rule re-checked immediately before key use | E-20, G-04 | OK |
| 14 | Replay keys bind action, RP, origin context, challenge; consumed on every result | SE-06 to SE-08 | OK |
| 15 | credProtect/backend requirements never weaken evidence | E-23 | OK |
| 16 | Durable pre-execution audit reservation | A-01 | OK |
| 17 | Counters/credential updates use the backend's shared operation lock | OS-02, M-03 | OK |
| 18 | Reload, revocation, expiry, principal death, browser shutdown invalidate authority; additive grant is not a change | S-05, SE-09, SE-10, GS-09 | OK |
| 19 | Same-user registration writes only to human backend, only under explicit exact-RP rule | RE-01, RE-02, V-03 | OK |
| 20 | Isolated registration writes only to its profile backend | RE-01, `test_e2e_registration_via_extension` | OK |
| 21 | Origin/RP validation per WebAuthn; explicit ports not rejected | B-09 | OK |
| 22 | Unsupported algorithms, attestation, extensions, iframe contexts, authenticator-selection fail closed | RE-06, B-08, `a_platform_attachment_is_not_supported_but_cross_platform_is_fine`, `test_unsupported_algorithm_is_a_deny_not_an_allow` | OK |
| 23 | Agent failure cannot disable/weaken the human path | G-02 | OK |
| 24 | No CTAP/UHID transport for agents | M-07 | OK |
| 25 | Managed browser never reaches the human authenticator | E-04 to E-14, E2E-45, E2E-46 | OK |

## §15-§18 Threat table, consequences, alternatives, code map

| ID | Decision | Ph | Evidence | St | Note |
|---|---|---|---|---|---|
| TH-01 | Threat-table mitigations (explicit mode, exact rules, short sessions, budgets, selectors, audit; one prompt/profile, queue, cooldown, cap; verified sender; daemon-owned store; no `confirm`; replay key; budget after validation; bearer + TTL; origin only from browser) | P4-P10 | each maps to R-01, F-01 to F-11, H-01 to H-08, GS-01 to GS-11, SE-06, H-07, X-10, B-07 | OK | every row's mitigation has an item above; residual-risk cells are documentation |
| AL-01 | Rejected alternatives that imply removal: UHID agent endpoint, MAIN-world override, operator-minted grants, CLI/API approval, native fallback | P2, P3, P6, P7 | files `endpoint_manager.rs`, `ceremony*.rs`, `device.rs`, `interaction.rs`, `intent.rs`, `storage.rs`, `main.js`, `broker.js`, `tools/agent-uhid-feasibility` absent; symbols `request_registration_grant`, `RegistrationGrantRegistry`, `RequestRegistration`, `human_interaction_required`, `install-native-messaging` absent | OK | |
| CM-01 | Code map §18 file list exists (runtime, sign, register, policy_engine, grant, prompt, audit, audit_events, backend, browser, launcher, cdp_bootstrap, granted_rules, identity; core config.rs/policy.rs; extension dir; sign-proxy.rs; both systemd units) | P11 | all present | OK | |
| CM-02 | `agent/ceremony.rs:1426-1479` and other "Removed" entries | P3 | removed | OK | |
| LG-01 | Leftover: `PrincipalResponse::SignAssertionResult` (C/protocol.rs:501) and `intent`-named grant tests remain although §19 says the `SignAssertion` principal request is removed | P11 | `PrincipalRequest` has no sign variant | OK | informational: only the response variant and internal `SignAssertionRequest` type remain |

## Counts by status

Counted over the 192 rows of the §1-§13 ID tables (the §14 invariant rows are a cross-reference and are counted
separately; the §15-§18 rows are a summary). At the audit: 176 OK, 10 NO-TEST, 1 NO-CODE, 5 DIVERGES. After the closing
commits:

| Status | Items |
|---|---|
| OK | 192 |
| NO-TEST | 0 |
| NO-CODE | 0 |
| DIVERGES | 0 |

Closed since the audit: R-04 (code), S-02, C-02, C-04, E-03, E-23 (level 2 implemented), RG-05, GS-02, GS-06, A-11,
DA-06 (tests), C-03, V-04, RE-06, A-13 (ADR amended, code was right), GS-01 (code: `StateDirectory=`).
§14 invariants (25): 25 OK. §15-§18 summary rows: 5 OK.

## E2E catalogue check (plan lines 659-716)

| ID | Scenario file | Test title id present | Catalogue "C" vs `ci:` | Note |
|---|---|---|---|---|
| 01 | e2e-01-same-user-allow | yes | C = ci | |
| 02 | e2e-02-isolated-allow | yes | C = ci | |
| 03 | e2e-03-deny-rule | yes | C = ci | |
| 04 | e2e-04-unlisted-rp | yes | C = ci | |
| 05 | e2e-05-raw-allow-credentials | yes | - | |
| 06 | e2e-06-localhost-rp | yes | C = ci | |
| 07 | e2e-07-credential-selection | yes | - | `first-matching` not exercised (catalogue does not list it) |
| 08 | e2e-08-popup-and-iframe | yes | - | |
| 09 | e2e-09-confirm-denied | yes | C = ci | file name still says `confirm` |
| 10 | e2e-10-cross-origin-iframe | yes | C = ci | |
| 11 | e2e-11-registration-after-exit | yes | C = ci | |
| 12 | e2e-12-exact-beats-wildcard | yes | C = ci | plus `E2E-12/audit-rule` |
| 13 | e2e-13-legacy-config | yes | ci:true, catalogue has no C | harmless extra |
| 14 | e2e-14-replay-identical-options | yes | C = ci | |
| 15 | e2e-15-budget-flood | yes | C = ci | |
| 16 | e2e-16-native-credential | yes | C = ci | |
| 17 | e2e-17-abort-signal | yes | C = ci | plus `/after-key-use` |
| 18 | e2e-18-worker-stopped-between | yes | - | |
| 19 | e2e-19-worker-killed-mid-request | yes | - | |
| 20 | e2e-20-long-wait | yes (`E2E-20`, `E2E-20/escalation`) | no C (not ci) | Closed: the catalogue no longer marks it C; it is local-full only because it takes 6 min per variant |
| 21 | e2e-21-escalation-timeout | yes | - | |
| 22 | e2e-22-concurrent-tabs | yes | - | |
| 23 | e2e-23-escalation-grants | yes | C = ci | |
| 24 | e2e-23-escalation-grants | yes | C = ci | |
| 25 | e2e-23-escalation-grants | yes | C = ci | |
| 26 | e2e-26-escalation-queue | yes | - | queue bound unit-covered only (catalogue text says so) |
| 27 | e2e-27-escalation-registration | yes | C = ci | |
| 28 | e2e-27-escalation-registration | yes | C = ci | |
| 29 | e2e-29-escalation-bus | yes | C = ci | |
| 30 | e2e-29-escalation-bus | yes | - | |
| 31 | e2e-31-grants-cli | yes | C = ci | |
| 32 | e2e-32-audit-content | yes | C = ci | plus `/abort` |
| 33 | e2e-33-deployment-axes | yes | ci:true, catalogue has no C | distinct-UID column unit-level (catalogue allows) |
| 34 | e2e-34-playwright-mcp | yes | C = ci | plus `/default-npx` |
| 35 | e2e-34-playwright-mcp | yes | C = ci | |
| 36 | e2e-36-chrome-devtools-mcp | yes | - (`ci:false`) | |
| 37 | e2e-37-connect-over-cdp | yes | C = ci | |
| 38 | e2e-38-39-optional-tools | yes | - | SKIP-OPT when browser-use absent: allowed ("local, optional") |
| 39 | e2e-38-39-optional-tools | yes | - | SKIP-OPT when agent-browser absent: allowed ("local, optional") |
| 40 | none (matrix run) | n/a | - | no scenario file by design (README: "E2E-40 is the matrix itself"); no recorded matrix run after P7 |
| 41 | e2e-41-refused-browsers | yes | C = ci | |
| 42 | e2e-42-dunst | yes | - | SKIP-OPT when dunst absent: the catalogue row now says "local, optional" (closed) |
| 43 | e2e-43-escalation-human | yes | - | |
| 44 | e2e-43-escalation-human | yes (`E2E-44`, `E2E-44/startup-refusal`) | - | |
| 45 | e2e-45-never-native | yes (plus `/cdp-context`) | C = ci | Closed by decision: the "extension unloaded after attach" case is removed from the catalogue row and recorded in the plan as not testable end to end (no product or supported harness path unloads the extension; a debug-only daemon hook would be unexercised product code). Covered by E-12 (interception degrades and the endpoint is withheld), E2E-47/unloadable (launch) and E2E-46 (layer 3) |
| 46 | e2e-46-private-dev (also a title in e2e-45 file comment) | yes (plus `/refused`, `/session-scope`) | C = ci | |
| 47 | e2e-47-missing-extension | yes (plus `/unloadable`) | C = ci | |
| 48 | e2e-48-escalation-caps | yes | C = ci | |
| 49 | e2e-29-escalation-bus | yes | - | |
| 50 | e2e-23-escalation-grants | yes | C = ci | |
| 51 | e2e-51-unfocused-create | yes | - | |

`xfailUntil` / `xfailMatch`: none left in `tests/agent-e2e/scenarios/*.js` (no `xfail` string at all). Remaining mentions are
only in `README.md`, `BASELINE.md` (historic tables) and `lib/scenario.js`.
SKIP-OPT users: `skipOptional` is called only by E2E-38, E2E-39 and E2E-42.

## §19 implementation status check

Rows: 52. Every row's Current cell starts with "Done" except two, which are now labelled accepted residuals.

| Row | Current | Issue |
|---|---|---|
| Unfocused-tab registration | "Accepted residual: a documented limitation (P6, P11), not open work for this ADR" | Closed: the ADR row, its status line and the plan's Final gate now call it an accepted residual; "all Done" means every other row |
| Distinct-UID systemd baseline | "Done for the baseline directives. Accepted residual: the evaluated directives" | Closed: stale line reference replaced by the unit's block and `systemd_unit_baseline.rs`; the evaluated directives are the accepted residual named in the Final gate |
| Operator-minted enrollment grants (#411) | Done (P3) | Closed: the "denies with audit until P7" text now says `register = "request"` escalates to one human-approved registration (8.3) |
| Supported browsers (and others) | Done | OK |
| `credProtect` (pre-ADR) | now "Done (P5; levels corrected in the verification gate)", naming `cred_protect::satisfied` | Closed: level 2 was not enforced and the line references were wrong; level 2 is implemented and the row names the function, not lines. Unit tests cover levels 1 to 3 with and without `allowCredentials` |
| Audit before key use / Backend separation / Agents off / Session audit (pre-ADR) | line refs at `130eaa5` | Line refs are stale by design ("References are file:line at commit 130eaa5"): `backend.rs:18-73` ok (18..73), `audit.rs:163-164`, `audit.rs:1258`, `sign.rs:1516`, `config.rs:989`, `grant.rs:571/639` do not match the current files (e.g. `enabled` is at `C/config.rs:1177`, reservation at `sign.rs:1402`, grant records near `grant.rs:495`) |
| Legacy fields and `policy` alias | Done (P4) | Closed: §6.4, §16 and plan M4 now say "the release after next (R8)" too (V-04) |
| Escalation audit events | Done (P7, P8) | Closed: ADR §12 now lists `expired(reason=server_lost)` and `revoked(reason=policy_reload)` (A-13) |
| Policy digest | Done (P4, P7) | "Version 5": confirmed (`CURRENT_POLICY_VERSION = 5`, C/policy.rs:39) |
| Audit content | Done (P8) | "schema version 3": confirmed (`AUDIT_SCHEMA_VERSION = 3`, A/audit_events.rs:27) |
| Granted-rules location | Done (P7) | Closed: the system unit now has `StateDirectory=passless-agent` with `StateDirectoryMode=0700` (GS-01) |

ADR status line (line 6): "Implemented in P2 to P11; the rows ... that are not done are listed there, and the final verification gate (P12) is pending". Accurate.
Plan progress log: P8, P9, P10 and P11 are still marked pending-E2E in the plan; P12 not started. ADR §19 says Done for items whose E2E run is not yet recorded.

## P11 doc-vocabulary spot check

Searched the whole worktree (`confirm`, `supervised`, `delegated-session`, `delegated_session`, `registration_allowed`), excluding node_modules, target, .git:

- `docs/agents/migration.md` (lines 10, 20, 24, 31, 34, 39): the migration note, allowed.
- `docs/decisions/0014-agent-delegation.md` and `docs/plans/agent-delegation-implementation.md`: history/migration text, allowed.
- `docs/security/FURTHER_ANALYSIS.md:19`: "the `confirm` approval model it discusses no longer exists" - a status note, acceptable as a migration note.
- `confirm` elsewhere in docs is the `--confirm` CLI flag, ordinary English ("confirm group membership"), or unrelated ADRs (0003, plan portable-tpm); no `supervised`/`delegated-session`/`registration_allowed` outside the allowed files.
- Code: only the legacy config parser and its tests (`C/config.rs:386-388, 802-813, 961, 3949, 4214-4349`), `C/policy.rs:1181` (a negative assertion), and `tests/agent-e2e/scenarios/e2e-09-confirm-denied.test.js` / `e2e-13` comments.
- `tools/agent-validation/lib/credential-store.sh` and `tools/agent-validation/tests/test-uninstall-rehearsal.sh` called the hidden aliases `session` / `delegation`; closed: they now use `principals` and `sessions` (the harness mock follows). `tools/agent-validation/stages/real-rp.sh` and its test still use `delegation revoke` (a feasibility probe), out of scope here.
Result: P11's "no mention except migration notes" holds.
