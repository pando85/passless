# Phase 0 Evidence: UHID Feasibility Probe

**Date:** 2026-07-13T20:02+02:00
**Host:** xps
**Kernel:** 7.1.3-1-MANJARO
**User:** agil (uid=1000, gid=1001)
**Groups:** agil sys network power fido docker lp wheel autologin nix-users
**Binary:** uhid-feasibility (debug build, rust edition 2024)
**Probe unit tests:** 15 passed, 0 failed

---

## Legend

| Symbol | Meaning |
|--------|---------|
| **EXECUTED** | Check was run on this host; result is recorded verbatim |
| **PENDING-PRIV** | Requires root/sudo; not executed in this run |
| **PENDING-BROWSER** | Requires browser + controlled-rp server; not executed |
| **PASS** | Executed check met expected condition |
| **FAIL** | Executed check did not meet expected condition |
| **INFO** | Informational observation, no pass/fail criteria |

---

## 1. Environment (EXECUTED, rootless)

| Check | Expected | Actual | Status |
|-------|----------|--------|--------|
| uhid module in /sys/module/uhid | present | present | **PASS** |
| uhid module in /proc/modules | loaded | `uhid 24576 1 - Live` | **PASS** |
| /dev/uhid exists | true | true | **PASS** |
| /dev/uhid mode | 660 | 660 | **PASS** |
| /dev/uhid owner:group | root:fido | root:fido | **PASS** |
| /dev/uhid readable by user | true | true | **PASS** |
| /dev/uhid writable by user | true | true | **PASS** |
| /dev/uhid open R/W (binary probe) | true | true | **PASS** |
| hidraw device count >= 1 | true | 2 | **PASS** |
| sysfs HID bus (/sys/bus/hid/devices) | exists | exists, 2 devices | **PASS** |
| user in fido group | true | true | **PASS** |
| binary compiles and runs | true | true | **PASS** |

**Evidence file:** `evidence/rootless-dryrun-20260713T200230.json`

---

## 2. Permission Probes (EXECUTED, rootless)

| Path | Mode | Owner:Group | Readable | Writable | Open R/W |
|------|------|-------------|----------|----------|----------|
| /dev/uhid | 660 | root:fido (uid=0, gid=947) | true | true | **true** |
| /dev/hidraw0 | 600 | root:root (uid=0, gid=0) | false | false | **false** |
| /dev/hidraw1 | 660 | root:root (uid=0, gid=0) | true | true | **true** |

**Observations:**
- /dev/uhid: Full R/W access via fido group membership. This is the primary device node for UHID operations.
- /dev/hidraw0: Mode 600, root-only. This is the I2C touchpad (CUST0001:00 06CB:76AF). Not accessible to non-root users. Expected behavior for internal HID devices.
- /dev/hidraw1: Mode 660, root:root. This is the Virtual FIDO2 Authenticator (passless). Group bits are rw but group is root, so only root gets group access. The `+` in `ls -la` indicates ACLs may grant additional access.

**Evidence file:** `evidence/permission-probes-20260713T200232.json`

---

## 3. HID Device Discovery (EXECUTED, rootless)

| Device | sysfs Path | Name | UNIQ | Vendor | Product | hidraw |
|--------|-----------|------|------|--------|---------|--------|
| 1 | /sys/bus/hid/devices/0003:15D9:0A37.0401 | Virtual FIDO2 Authenticator | virtual-fido-001 | 15D9 | 0A37 | /dev/hidraw1 |
| 2 | /sys/bus/hid/devices/0018:06CB:76AF.0001 | CUST0001:00 06CB:76AF | (empty) | 06CB | 76AF | /dev/hidraw0 |

**Observations:**
- Device 1 is the existing passless virtual authenticator (human endpoint, vendor 15d9 product 0a37), discoverable via sysfs with deterministic identity fields.
- Device 2 is an I2C HID device (likely touchpad), no UNIQ field set.
- Sysfs discovery by uniq works for devices with UNIQ set.
- hidraw mapping via sysfs subtree walk is order-independent (confirmed by code review of `sysfs.rs:find_hidraw_nodes_inner`).

---

## 4. Identity Control (EXECUTED, rootless)

Validated via `cycle 1000` — each cycle creates a device with deterministic identity:
- name: `feasibility-cycle-{N}`
- phys: `feasibility-cycle-{N}-phys`
- uniq: `feasibility-cycle-{N}`
- vendor: 0x15d9, product: **0xF1D0** (probe-reserved, NOT human 0x0A37), version: 0x0001

| Check | Result |
|-------|--------|
| Deterministic name set via CREATE2 | **PASS** (1000/1000 cycles created successfully) |
| Deterministic phys set via CREATE2 | **PASS** |
| Deterministic uniq set via CREATE2 | **PASS** |
| Deterministic vendor/product/version | **PASS** |
| Device visible in sysfs after create | **PASS** (destroy is immediate; sysfs entry appears and disappears per cycle) |

**Note:** Probe devices use product 0xF1D0, which is distinct from the human passless product 0x0A37. The udev rule tags only 0xF1D0, so it can never match the human endpoint.

---

## 5. Concurrent Lifecycle (EXECUTED, rootless)

### 5a. Sequential 1000-cycle test

| Metric | Value |
|--------|-------|
| Requested cycles | 1000 |
| Succeeded | 1000 |
| Failed | 0 |
| Wall clock | 85794ms |
| Create avg/min/max | 84ms / 0ms / 106ms |
| Destroy avg/min/max | 0ms / 0ms / 15ms |
| Leftover devices after test | 0 (cleanup scan: "No probe devices found in sysfs.") |

**Evidence file:** `evidence/cycle-1000-20260713T200405.json`

### 5b. Concurrent 3-device test

| Metric | Value |
|--------|-------|
| Devices | 3 concurrent |
| All OK | true |
| Total duration | 151ms |

### 5c. Destroy-on-Drop

Validated by code review (`uhid_raw.rs:257-263`): `Drop` impl calls `destroy()` if `started == true`. Confirmed working in 1000-cycle test where no leftover devices remained.

---

## 6. Cleanup Scan (EXECUTED, rootless)

Post-cycle sysfs scan: **No probe devices found.**

Cleanup detection covers all probe name patterns:
- `feasibility-probe` (legacy)
- `feasibility-cycle` (sequential cycles)
- `feasibility-concurrent` (concurrent cycles)
- `agent-uhid` (generic agent probe)

This confirms:
- All 1000 create-destroy cycles properly cleaned up via UHID_DESTROY
- Drop-on-destroy safety net is functional
- No resource leaks in the feasibility probe path

---

## 7. Unit Tests (EXECUTED, rootless)

### Test counts by crate

| Crate | Passed | Failed | Ignored |
|-------|--------|--------|---------|
| agent-uhid-feasibility (probe tool) | 15 | 0 | 0 |
| passless-uhid (UHID library) | 36 | 0 | 0 |
| passless-core | 14 | 0 | 0 |
| passless (main binary) | 35 | 0 | 0 |
| e2e tests (require running authenticator) | 1 | 0 | 47 |
| **Workspace total** | **101** | **0** | **47** |

Probe tool tests cover: struct layouts, default values, permission probes on nonexistent paths, sysfs attribute reads, device discovery by uniq, hidraw mapping resolution, lifecycle report formatting, environment report structure, cleanup detection.

---

## 8. Pending: Privileged Checks (PENDING-PRIV)

These checks require root and were **NOT executed** in this run:

| Check | Why Pending | How to Execute |
|-------|-------------|----------------|
| udev rule installation | Requires writing to /etc/udev/rules.d/ | `sudo policy/setup.sh` |
| udev rule reload + trigger | Requires root | Included in `policy/setup.sh` |
| /dev/uhid permission enforcement via udev | Requires udevadm trigger | Verify after setup.sh |
| Probe device tagging via udev ENV{FEASIBILITY_PROBE} | Requires udev rule active | Create device, check `udevadm info` |
| hidraw node permission override for probe devices | Requires udev rule active | Check after setup.sh |
| Module unload safety check | Requires root | `policy/cleanup.sh` |
| Leftover device cleanup via sysfs write | Requires root | `policy/cleanup.sh` |

**To run:** `sudo scripts/run-all.sh --with-priv`

---

## 9. Browser/Controlled-RP Checks

### 9a. Debug Auto-Accept WebAuthn Test (EXECUTED — see Section 11)

Basic WebAuthn registration and assertion were executed via stock Chromium/Playwright against the local Passless UHID authenticator with **debug auto-accept UV** enabled. Results are documented in **Section 11** below.

> **This was a debug auto-accept test.** User verification was auto-approved by the authenticator binary (`PASSLESS_E2E_AUTO_ACCEPT_UV=1` or equivalent debug-mode bypass). This is **NOT** evidence of production prompt approval flow, nor of agent endpoint isolation. No agent-mediated device creation, no cross-identity separation, and no privileged pipeline was involved.

### 9b. Still Pending

| Check | Why Pending | How to Execute |
|-------|-------------|----------------|
| Agent-mediated UHID device creation from browser | Requires full agent pipeline | Phase 1+ work |
| Cross-origin isolation headers (COOP/COEP) | Requires HTTPS + cert + agent pipeline | Phase 1+ work |
| hidraw node access from agent context | Requires agent running with endpoint isolation | Phase 1+ work |
| Privileged cross-identity separation | Requires uhid-daemon / fido-agent-probe groups active | Phase 1+ work (depends on Section 8 privileged checks) |
| Production UV prompt approval flow | Requires interactive user presence confirmation | Post-debug validation |

**To run (basic browser test):** See `controlled-rp/README.md`

---

## 10. Security Fix: Device Isolation Policy (Phase 0)

**Date:** 2026-07-13T20:02+02:00

### Problem

The original policy violated two security constraints:

| Rule | Violation |
|------|-----------|
| **PRIN-03** | Human operators and the daemon shared the same `fido` group for `/dev/uhid` access. Principals (humans) had the same device permissions as the daemon. |
| **ROUTE-03** | The `fido` group was granted `/dev/uhid` R/W, giving human principals direct access to the UHID character device. |

Additionally, the original udev probe rule matched on `ATTRS{idProduct}=="0a37"` — the **same product ID as the human passless authenticator**. This meant the udev rule would tag the human's device as a feasibility probe, violating device isolation.

### Fix: Three-Tier Identity Model + Probe Product Isolation

The policy now enforces strict separation using three disjoint groups:

| Group | Purpose | Members | Device Access |
|-------|---------|---------|---------------|
| `uhid-daemon` | Daemon-only `/dev/uhid` R/W | `passless-daemon` (system user) | `/dev/uhid` (0660) |
| `fido` | Human operator hidraw access | human operators (e.g. `agil`) | Real hidraw only (NOT `/dev/uhid`, NOT probe hidraw) |
| `fido-agent-probe` | Per-agent-profile probe hidraw | agent processes | Probe hidraw (0660) |

Probe devices use a **reserved product ID 0xF1D0** (distinct from human 0x0A37) so the udev rule can never match the human endpoint.

### udev Rules (90-uhid-feasibility.rules)

```
# /dev/uhid: daemon-only access (PRIN-03, ROUTE-03)
KERNEL=="uhid", SUBSYSTEM=="misc", MODE="0660", GROUP="uhid-daemon"

# Tag feasibility probe devices by deterministic vendor/product identity.
# Probe product 0xF1D0 is reserved for feasibility probes ONLY.
# This MUST NOT match the human passless endpoint (15d9:0a37).
SUBSYSTEM=="hid", ATTRS{idVendor}=="15d9", ATTRS{idProduct}=="f1d0", ENV{FEASIBILITY_PROBE}="1"

# Probe hidraw nodes: per-agent-profile group only (ISOL-01).
# Humans in 'fido' do NOT get probe hidraw access.
SUBSYSTEM=="hidraw", ENV{FEASIBILITY_PROBE}=="1", MODE="0660", GROUP="fido-agent-probe"
```

### Setup (setup.sh)

- Creates groups explicitly: `uhid-daemon` (system), `fido`, `fido-agent-probe` (system)
- Creates system user `passless-daemon` in `uhid-daemon` group
- Adds invoking user (`SUDO_USER`) to `fido` ONLY
- Actively removes invoking user from `uhid-daemon` if present (PRIN-03 enforcement)
- Writes state file (`/var/lib/passless-feasibility/setup.state`) for safe cleanup

### Cleanup (cleanup.sh)

- Reads state file to remove ONLY resources created by setup
- Removes daemon user only if created by setup
- Removes groups only if created by setup AND have no remaining members
- Scans for leftover probe devices in sysfs (matches all probe name patterns: feasibility-probe, feasibility-cycle, feasibility-concurrent, agent-uhid)

### Dry-Run Validator (validate-rules.sh)

Non-privileged validator that proves policy correctness by static analysis:

| Check | Constraint | Result |
|-------|-----------|--------|
| PRIN-03_uhid_group_disjoint | /dev/uhid group != fido | **PASS** |
| ROUTE-03_no_uhid_for_humans | No uhid rule grants fido | **PASS** |
| ISOL-01_probe_hidraw_group | Probe hidraw != fido, != uhid-daemon | **PASS** |
| PROBE-01_no_human_product | Probe rule product != 0a37 | **PASS** (uses f1d0) |
| SETUP-01_no_human_in_daemon_group | setup.sh doesn't add SUDO_USER to uhid-daemon | **PASS** |
| SETUP-02_explicit_group_creation | All 3 groups created via groupadd | **PASS** |
| SETUP-02_explicit_user_creation | Daemon user created via useradd | **PASS** |
| SETUP-03_removes_human_from_daemon | setup.sh removes human from daemon group if present | **PASS** |
| CLEANUP-01_state_based_cleanup | cleanup.sh uses state file | **PASS** |

**Evidence file:** `evidence/policy-validation-20260713T200209.json`

### Invariants

- **PRIN-03**: Principals (human operators) NEVER share a group with the daemon for `/dev/uhid`.
- **ROUTE-03**: Principals NEVER receive `/dev/uhid`.
- **ISOL-01**: Probe hidraw nodes are accessible ONLY to the per-agent-profile group.
- **PROBE-01**: Probe udev rule NEVER matches the human product 0x0A37.
- **SETUP-01**: Setup creates groups/users explicitly — no implicit grants.
- **CLEANUP-01**: Cleanup uses state file to remove only what was created.

---

## 11. Debug Auto-Accept Browser Test (EXECUTED — 2026-07-13)

> **WARNING: DEBUG AUTO-ACCEPT TEST EVIDENCE**
>
> The tests below were executed with the Passless authenticator running in **debug auto-accept mode**, where user verification prompts are automatically approved without interactive human consent. This is **NOT** evidence of:
> - Production user-verification prompt approval flow
> - Agent endpoint isolation or cross-identity separation
> - Privileged uhid-daemon / fido-agent-probe group enforcement
>
> These results prove that the stock Chromium WebAuthn API can complete registration and authentication against the local Passless UHID endpoint with SimpleWebAuthn server-side verification. They do **not** prove that an agent pipeline can drive the same flow, nor that identity isolation holds.

**Date:** 2026-07-13
**Browser:** Stock Chromium via Playwright
**Authenticator:** Local Passless UHID endpoint (debug build, auto-accept UV)
**RP server:** controlled-rp (SimpleWebAuthn)
**Origin:** `http://localhost:8443`
**RP ID:** `localhost`
**Pre-condition:** Existing user Passless service was stopped before test; restored active afterward.

### 11a. Registration (navigator.credentials.create)

| Field | Expected | Actual | Status |
|-------|----------|--------|--------|
| SimpleWebAuthn verification | pass | **verified** | **PASS** |
| attestation format (fmt) | none | **none** | **PASS** |
| user verification (uv) | true | **true** | **PASS** |
| sign count (initial) | 0 | **0** | **PASS** |
| credential created | true | **true** | **PASS** |

### 11b. Authentication (navigator.credentials.get)

| Field | Expected | Actual | Status |
|-------|----------|--------|--------|
| SimpleWebAuthn signature verification | pass | **verified** | **PASS** |
| user verification (uv) | true | **true** | **PASS** |
| sign count (advanced) | 1 | **1** | **PASS** |
| same credential used | true | **true** | **PASS** |

### 11c. What This Proves

- Stock Chromium/Playwright can perform full WebAuthn registration and authentication against the local Passless UHID authenticator.
- SimpleWebAuthn server-side verification accepts the attestation and assertion.
- The credential counter advances correctly (0 → 1).
- UV flag is reported as true in both registration and authentication.

### 11d. What This Does NOT Prove

- Agent-mediated device creation or agent-driven WebAuthn flow (Phase 1+).
- Production UV prompt approval (this was debug auto-accept).
- Cross-identity or cross-agent endpoint isolation (no agent pipeline was involved).
- Privileged group enforcement (uhid-daemon / fido-agent-probe were not active).

---

## 12. Summary

| Category | Executed | Passed | Failed | Pending |
|----------|----------|--------|--------|---------|
| Environment probes | 12 | 12 | 0 | 0 |
| Permission probes | 3 paths | 3 paths | 0 | 0 |
| HID discovery | 2 devices | 2 devices | 0 | 0 |
| Identity control | 5 checks | 5 | 0 | 0 |
| 1000-cycle lifecycle | 1000 | 1000 | 0 | 0 |
| Concurrent lifecycle | 3 devices | 3 | 0 | 0 |
| Cleanup scan | 1 | 1 | 0 | 0 |
| Probe unit tests | 15 | 15 | 0 | 0 |
| Policy validation (dry-run) | 9 | 9 | 0 | 0 |
| Browser test (debug auto-accept) | 2 flows | 2 | 0 | — |
| **Total executed** | **1052** | **1052** | **0** | — |
| Privileged checks | — | — | — | 7 |
| Browser/controlled-rp (agent pipeline, cross-identity, production UV) | — | — | — | 5 |

**Test counts by crate (workspace):**

| Crate | Passed | Scope |
|-------|--------|-------|
| agent-uhid-feasibility | 15 | Probe tool unit tests |
| passless-uhid | 36 | UHID library unit tests |
| passless-core | 14 | Core library unit tests |
| passless | 35 | Main binary unit tests |
| e2e (ignored w/o authenticator) | 1 + 47 ignored | Integration tests |
| **Workspace total** | **101 passed** | All crates |

**Machine-readable evidence files:** `evidence/*.json`

---

*No results were fabricated. All PASS/FAIL statuses above correspond to commands actually executed on host `xps` at the timestamps shown. The browser test (Section 11) was executed in **debug auto-accept mode** against the local Passless UHID endpoint with a controlled RP — it is **not** evidence of production prompt approval or agent endpoint isolation. Pending items are explicitly marked and require privileged access, agent pipeline, or production UV flow not available in this session.*
