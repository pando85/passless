# Security Analysis: Critical Issues Requiring Further Investigation

## Overview

This document catalogs critical and high-severity security issues identified in the Passless agent architecture that require deeper architectural analysis before remediation. These issues span three attack surfaces:

1. **Same-user browser hardening** — When the daemon and browser run under the same UID, the hardening path is intentionally bypassed to accommodate Chromium's setuid sandbox helper. This creates a privilege inheritance chain where a compromised browser inherits the daemon's full privilege context.

2. **Authorization model** — The agent internally requests and approves its own authentication grants using a sealed `AdminAuthority` token that can be constructed by any code path within the process, effectively making the agent both requester and approver.

3. **Notification-based approval** — User verification relies on D-Bus desktop notifications whose action signals can be synthetically injected by any process on the same session bus.

Each issue is analyzed with current state, attack scenarios, proposed solutions, and an implementation plan. These are not theoretical concerns — they represent concrete gaps between the documented security architecture and the actual implementation.

---

## Priority 1: Same-User Browser Hardening

### C-1: Same-User Port-Mode Browser Spawns with Zero Hardening

> **Status: Accepted — by design.** Superseded by
> [ADR 0008](../decisions/0008-same-user-trust-boundary.md). In same-user mode the browser
> and daemon share a UID, so no kernel boundary exists regardless of spawn-time hardening;
> the security controls live in the policy layer. The analysis below is kept for
> historical context but its severity framing no longer applies. Residual items (FD
> hygiene, PDEATHSIG, rlimits) are resilience follow-ups, not security fixes.

**File:** `cmd/passless/src/agent/browser.rs:1998-2035`

**Current State:**

When `is_trusted_same_user_port_launch()` returns `true` (daemon UID != 0, and target UID/GID match daemon UID/GID), the `pre_exec` closure in `spawn_browser_port_mode()` skips `setup.apply()` entirely:

```rust
// browser.rs:2020-2034
unsafe {
    cmd.pre_exec(move || {
        if trusted_same_user {
            // Do not set PR_SET_NO_NEW_PRIVS before exec in trusted
            // same-user mode. Chromium may need its setuid sandbox helper
            // during startup.
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        } else {
            setup.apply(&[0, 1, 2])
        }
    });
}
```

The `HardenedChildSetup::apply()` method (`launcher.rs:690-756`) provides:
- `PR_SET_NO_NEW_PRIVS` — prevents privilege escalation via setuid binaries
- `close_range` — closes all inherited file descriptors
- `setuid`/`setgid` — drops to target identity
- Resource limits (`RLIMIT_NOFILE`, `RLIMIT_NPROC`, `RLIMIT_CORE`, `RLIMIT_AS`)

**None of these are applied** in same-user port mode. The browser child inherits:
- All open file descriptors from the daemon (including `/dev/uhid`, any storage backend handles, pipe endpoints)
- The daemon's full resource limits
- No `PR_SET_NO_NEW_PRIVS` — can exec setuid binaries
- The daemon's complete privilege context

**Attack Scenarios:**

1. **Browser exploit → daemon compromise:** A vulnerability in Chromium (renderer, V8, GPU process) allows arbitrary code execution. The exploited process inherits the daemon's UID, open file descriptors to `/dev/uhid`, credential storage, and any other daemon resources. The attacker gains the daemon's full privilege context.

2. **FD leakage to renderer:** Without `close_range`, any file descriptors the daemon has open (credential storage files, UHID device handles, log sockets) are accessible to the browser's renderer process through `/proc/self/fd/`.

3. **Setuid escalation:** Without `PR_SET_NO_NEW_PRIVS`, the browser process can exec setuid-root binaries (e.g., `sudo`, `pkexec`) to attempt privilege escalation.

**Why the bypass exists:**

The comment states Chromium may need its setuid sandbox helper (`chrome-sandbox`) during startup. Chromium's sandbox requires either:
- A setuid-root helper binary, or
- An unprivileged user namespace (`user_namespaces(7)`)

When `PR_SET_NO_NEW_PRIVS` is set, the setuid sandbox helper cannot elevate privileges. However, modern Chromium (>= 120) can fall back to unprivileged user namespaces if available, making the NNP bypass unnecessary on most current distributions.

---

### C-2: Daemon Runs as Root with NoNewPrivileges=false and Full /dev Access

> **Status: Open — re-scoped to root multi-principal deployment only.** See
> [ADR 0009](../decisions/0009-daemon-hardening-scope.md). Same-user deployments are out
> of scope (daemon is unprivileged there; trust boundary is the session per ADR 0008).
> Open items are an implementation backlog for the isolated mode: C-2a additive systemd
> directives, C-2b evaluated directives (`CapabilityBoundingSet`, `SystemCallFilter`),
> and the deferred question of running with a bounded capability set instead of root.

**File:** `contrib/systemd/passless-agent.service:37,42`

**Current State:**

The systemd service file explicitly disables two critical hardening directives:

```ini
# Process
NoNewPrivileges=false
# Note: NoNewPrivileges=false is required because the daemon uses setuid to
# launch principal and browser processes under separate Unix identities.

# Namespaces
PrivateDevices=false
# PrivateDevices cannot be enabled: Chromium enumerates dynamically created host
# hidraw nodes after service startup, so static bind mounts are insufficient.
```

The daemon **must** run as root for:
- Creating UHID endpoints (`/dev/uhid`)
- `setuid`/`setgid` to launch principal processes under separate UIDs
- Managing per-profile device policy via hidraw udev rules

**Impact:**

If the daemon process itself is compromised (e.g., through a vulnerability in CTAP command parsing, CBOR deserialization, or the credential storage backend), the attacker has:
- Root access to the entire system
- Access to `/dev/uhid` — can create arbitrary HID devices
- Access to all hidraw devices — can intercept security key communications
- Ability to read/write any file on the system
- Ability to load kernel modules (unless `ProtectKernelModules` blocks it, which it does — see line 61)

**Mitigations already in place:**
- `ProtectSystem=strict` — read-only `/usr`, `/boot`, `/efi`
- `ProtectHome=read-only` — read-only home directories
- `PrivateTmp=true` — isolated `/tmp`
- `ProtectKernelTunables=true` — read-only `/proc/sys`, `/sys`
- `ProtectControlGroups=true` — read-only cgroup hierarchy
- `ProtectKernelModules=true` — cannot load kernel modules
- `RestrictSUIDSGID=true` — cannot create setuid/setgid files

**Missing hardening directives that should be evaluated:**
- `ProtectHostname=true` — prevents hostname changes
- `ProtectClock=true` — prevents system clock changes
- `ProtectKernelLogs=true` — prevents access to kernel log ring buffer
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` — limits socket families
- `RestrictNamespaces=true` — prevents creating new namespaces
- `LockPersonality=true` — prevents changing execution domain
- `MemoryDenyWriteExecute=true` — prevents W^X memory mappings (may conflict with JIT)
- `RestrictRealtime=true` — prevents realtime scheduling
- `SystemCallFilter=` — seccomp-BPF syscall whitelist

---

### H-2: No Namespace Isolation for Browser Processes

> **Status: Open — re-scoped to isolated (cross-user) deployment mode only.** See
> [ADR 0010](../decisions/0010-namespace-isolation-scope.md). Out of scope for same-user
> mode (ADR 0008). Deferred backlog: mount namespace first with bind-mount allowlist,
> PID namespace as stretch, network namespace only in pipe mode (port mode incompatible).
> Terminology: `AgentMode::Isolated` means credential isolation, not OS namespaces.

**File:** `cmd/passless/src/agent/browser.rs:1869-1912, 2000-2035`

**Current State:**

Neither `spawn_browser_hardened()` nor `spawn_browser_port_mode()` create any Linux namespaces for the browser child process. The `HardenedChildSetup::apply()` method (`launcher.rs:690-756`) performs:
- `setsid()` — new session
- `prctl(PR_SET_PDEATHSIG)` — parent death signal
- `setgroups`/`setgid`/`setuid` — identity change (cross-user only)
- `prctl(PR_SET_NO_NEW_PRIVS)` — no new privileges (cross-user only)
- `setrlimit` — resource limits (cross-user only)

**No `unshare()` calls are made.** The browser process runs in the same:
- Mount namespace as the daemon — full view of daemon's filesystem mounts
- PID namespace — can see and signal daemon processes
- Network namespace — shares daemon's network stack
- User namespace — same UID/GID mapping
- IPC namespace — shares daemon's IPC objects

The architecture documentation describes namespace isolation as a design goal, but the implementation does not create any namespaces. The `read_namespace_inodes()` function (`launcher.rs:314`) reads namespace inodes for **verification** of principal identity, not for **enforcement** of isolation.

**Attack Scenarios:**

1. **Filesystem access:** A compromised browser can traverse the daemon's mount namespace and access any file the daemon can read, including credential storage, configuration files, and other principals' data.

2. **Process interaction:** The browser can send signals to daemon processes (same PID namespace), potentially disrupting service or exploiting signal handlers.

3. **Network access:** The browser shares the daemon's network namespace and can access any network service the daemon can reach, including internal services.

---

### H-3: No seccomp-BPF Filter on Any Spawned Process

> **Status: Open — re-scoped to isolated (cross-user) mode only.** See
> [ADR 0011](../decisions/0011-seccomp-scope.md). Out of scope for same-user mode
> (ADR 0008). Deferred backlog: H-3a principal-process seccomp blacklist (early,
> maintainable — our own binary), H-3b browser chrome seccomp (deferred, requires
> per-version syscall profiling; Chromium version fragility risk).

**File:** `cmd/passless/src/agent/browser.rs:1880-1907, launcher.rs:690-756`

**Current State:**

No seccomp-BPF (Berkeley Packet Filter) syscall filter is installed on any spawned process — neither the browser nor principal processes. The `HardenedChildSetup::apply()` method does not call `prctl(PR_SET_SECCOMP)` or use `seccomp_init()`/`seccomp_rule_add()`/`seccomp_load()`.

The only syscall-related restriction is `PR_SET_NO_NEW_PRIVS`, which prevents privilege escalation but does not restrict which syscalls the process can invoke.

**Impact:**

A compromised browser or principal process has access to the full kernel syscall surface, including:
- `ptrace` — can trace and manipulate other processes (same UID)
- `mount` — can mount filesystems (if root)
- `bpf` — can load BPF programs (if CAP_SYS_ADMIN)
- `init_module`/`finit_module` — can load kernel modules (if CAP_SYS_MODULE)
- `kexec_load` — can load a new kernel (if CAP_SYS_BOOT)
- File creation, network access, process spawning — unrestricted

**Comparison with similar projects:**

- **Firejail:** Applies seccomp-BPF with a default blacklist of ~150 dangerous syscalls
- **Flatpak:** Applies seccomp-BPF with architecture-specific whitelists
- **systemd --user:** Can apply `SystemCallFilter=` per service
- **Chromium's own sandbox:** Applies seccomp-BPF to renderer and GPU processes

---

## Priority 2: Authorization Model

### C-3: Self-Approval of Authentication Grants

> **Status: Accepted (approval mechanism) / Open backlog (audit).** See
> [ADR 0012](../decisions/0012-grant-audit-and-notification-approval-integrity.md). Self-approval within
> configured policy is the designed autonomous behavior (ADR 0001/0007); the
> `AdminAuthority` seal is cosmetic and accepted as such. Open item: grant
> request/approval are not audited in production despite builders existing — backlog fix.

**File:** `cmd/passless/src/agent/runtime/browser_ensure.rs:398-409`

**Current State:**

When a principal requests a browser authentication session, the agent:

1. Creates a grant request via `admin_request_grant()` or `admin_request_dynamic_grant()` (`policy_engine.rs:1426-1448`)
2. Immediately approves it via `admin_approve_grant()` with `admin_authority()` (`policy_engine.rs:1450-1462`)

```rust
// browser_ensure.rs:398-409
// This is an internal approval, not admin IPC. The request reached this point only
// after principal capability/peer/process verification and explicit trusted port mode.
let grant_id = self
    .policy_runtime
    .admin_approve_grant(&request_id, &crate::agent::intent::admin_authority())
    .map_err(|e| { ... })?;
```

The `AdminAuthority` struct (`intent.rs:212-223`) is a zero-sized type with a private constructor:

```rust
pub struct AdminAuthority {
    _sealed: std::marker::PhantomData<()>,
}

impl AdminAuthority {
    fn new() -> Self {
        Self { _sealed: std::marker::PhantomData }
    }
}

pub(crate) fn admin_authority() -> AdminAuthority {
    ADMIN_AUTHORITY_TOKEN.fetch_add(1, Ordering::Relaxed);
    AdminAuthority::new()
}
```

The `ADMIN_AUTHORITY_TOKEN` is an `AtomicU64` counter that increments on each call but is never checked or validated. Any code within the crate can call `admin_authority()` to obtain an `AdminAuthority` token. There is no cryptographic binding, no external verification, and no separation of concerns.

**The comment says:** "This is an internal approval, not admin IPC. The request reached this point only after principal capability/peer/process verification and explicit trusted port mode."

**Impact:**

The self-approval pattern means:
1. **No independent authorization check:** The same process that receives the principal's request also approves the grant. There is no second party, no human-in-the-loop, and no external policy decision point.
2. **Grant = signing authority:** Once approved, the grant enables the browser to sign assertions for the requested RP IDs. The agent will sign any authentication challenge for any credential in the grant scope.
3. **No rate limiting or throttling:** Each grant request is immediately approved. A malicious principal that passes the initial verification can request unlimited grants.
4. **No audit trail of independent approval:** The approval is logged, but it is self-generated — it does not represent an independent decision.

**Trust model analysis:**

The current design relies on the assumption that the initial verification steps (principal capability, peer identity, process identity digest, trusted port mode) are sufficient to authorize all subsequent signing operations. This is equivalent to a "once verified, always trusted" model with no session-level re-authorization.

---

### H-1: D-Bus Notification Action Injection

> **Status: Open backlog — in scope for same-user mode.** See
> [ADR 0012](../decisions/0012-grant-audit-and-notification-approval-integrity.md). Injection collapses
> the human/agent distinction that `authorization="confirm"` relies on, so ADR 0008's
> trust-boundary reasoning does not exempt it. Planned fix: raw zbus signal handling that
> validates the `ActionInvoked` sender against the notification server's bus name
> (notify-rust 4.x `wait_for_action` does not expose the sender).

**File:** `cmd/passless/src/agent/prompt.rs:616-633`

**Current State:**

User verification for authentication and registration operations is performed through desktop notifications via the `notify-rust` crate, which communicates over the session D-Bus:

```rust
// prompt.rs:606-633
let mut notification = Notification::new();
notification
    .summary(&title)
    .body(&body)
    .icon("security-high")
    .timeout(Timeout::Milliseconds((self.timeout_secs * 1000) as u32))
    .urgency(Urgency::Critical)
    .action("approve", "Approve")
    .action("deny", "Deny");

let handle = match notification.show() { ... };

handle.wait_for_action(|action| {
    let mut result = action_result_clone.lock().expect("...");
    *result = Some(action.to_string());
});
```

The notification server is queried for capabilities (`prompt.rs:479-499`), and servers that only support default actions (notify-osd, mako, quickshell) are rejected. Only servers reporting `FullActions` capability are accepted.

**The D-Bus notification protocol:**

The Desktop Notifications Specification (`org.freedesktop.Notifications`) operates over the session D-Bus. The `ActionInvoked` signal is sent by the notification server when the user clicks an action button. However:

1. **Session D-Bus is shared:** Any process running as the same user on the same D-Bus session can send arbitrary messages to any service, including the notification server.
2. **No sender authentication:** The notification server does not cryptographically prove that an `ActionInvoked` signal corresponds to a physical user action. Any process can call `org.freedesktop.Notifications.ActionInvoked` on the server's bus name.
3. **Synthetic signals:** A malicious process can:
   - Send a `NotificationClosed` signal to dismiss the notification
   - Send an `ActionInvoked` signal with action `"approve"` to simulate user approval
   - Do this without any user interaction

**Mitigations already in place:**
- `min_review_delay_ms` — rejects approvals that arrive too quickly (default 1000ms)
- Server capability check — rejects servers that don't support full actions
- Action string validation — only `"approve"`, `"deny"`, and `"__closed"` are accepted

**Attack Scenarios:**

1. **Malicious process auto-approves:** A compromised process on the same user session sends a synthetic `ActionInvoked` signal with `"approve"` after the `min_review_delay_ms` has elapsed. The agent grants the authentication request without human interaction.

2. **Notification server compromise:** If the notification daemon itself has a vulnerability, an attacker can inject action signals.

3. **D-Bus policy bypass:** On some distributions, D-Bus policy rules may not restrict `ActionInvoked` signals to the notification server's bus name, allowing any process to inject them.

---

## Architectural Considerations

### Trade-offs Between Security and Usability

| Concern | Security Impact | Usability Impact |
|---------|----------------|-----------------|
| `PR_SET_NO_NEW_PRIVS` on same-user browser | Prevents setuid sandbox helper | Chromium may fail to start on systems without user namespaces |
| Mount namespace for browser | Isolates filesystem view | Breaks access to user's X11/Wayland socket, fonts, themes |
| seccomp-BPF on browser | Limits syscall surface | May break Chromium features (GPU, audio, DRM) |
| External approval for grants | Prevents self-approval | Requires separate approval mechanism or device |
| D-Bus notification hardening | Prevents action injection | May require custom notification daemon |

### Chromium Sandbox Requirements

Chromium requires one of two sandboxing mechanisms:

1. **Setuid sandbox (`chrome-sandbox`):** Requires a setuid-root helper binary. Blocked by `PR_SET_NO_NEW_PRIVS`. This is the legacy approach.

2. **Unprivileged user namespace sandbox:** Uses `CLONE_NEWUSER` to create a user namespace where Chromium can set up its sandbox without root. This is the modern approach (default since Chromium 120+). Requires:
   - `kernel.unprivileged_userns_clone=1` (Debian/Ubuntu) or `kernel.apparmor_restrict_unprivileged_userns=0` (Ubuntu 23.10+)
   - No `PR_SET_NO_NEW_PRIVS` before the namespace is created (Chromium sets NNP internally after sandbox setup)

**Key insight:** Chromium sets `PR_SET_NO_NEW_PRIVS` internally **after** its sandbox is established. The daemon's `pre_exec` NNP setting prevents Chromium from creating its own user namespace sandbox. This is the fundamental tension.

**Resolution path:** Instead of setting NNP in `pre_exec`, allow Chromium to create its own user namespace sandbox, then apply NNP via a different mechanism (e.g., systemd service for the browser, or a wrapper that sets NNP after Chromium has initialized its sandbox).

---

## Proposed Solutions

### Priority 1: Same-User Browser Hardening

#### C-1: Same-User Port-Mode Zero Hardening

**Solution A: Selective hardening (skip only NNP)**
- Apply `close_range`, `setsid`, `PR_SET_PDEATHSIG`, and resource limits in same-user mode
- Skip only `PR_SET_NO_NEW_PRIVS` and `setuid`/`setgid`
- **Pros:** Minimal change, preserves Chromium compatibility, closes FD leakage
- **Cons:** Still allows setuid escalation, no identity separation
- **Complexity:** Low

**Solution B: Deferred NNP via wrapper**
- Launch a small wrapper binary that:
  1. execs Chromium
  2. After Chromium's sandbox is initialized (detectable via a readiness signal), sets `PR_SET_NO_NEW_PRIVS` on itself
- **Pros:** Full hardening, Chromium-compatible
- **Cons:** Requires a new binary, complex synchronization
- **Complexity:** High

**Solution C: Rely on Chromium's user namespace sandbox**
- Remove the NNP bypass entirely
- Ensure the system has unprivileged user namespaces enabled
- Let Chromium create its own sandbox
- **Pros:** Simplest solution, uses Chromium's well-tested sandbox
- **Cons:** Fails on systems with user namespaces disabled, requires documentation
- **Complexity:** Low

**Recommended approach:** Solution A immediately (close FDs, apply resource limits), then Solution C as the default with a fallback mechanism for systems without user namespaces.

#### C-2: Systemd Hardening

**Solution A: Add missing directives**
- Add `ProtectHostname=true`, `ProtectClock=true`, `ProtectKernelLogs=true`
- Add `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
- Add `RestrictNamespaces=true` (conflicts with browser launch — needs evaluation)
- Add `LockPersonality=true`
- **Pros:** Defense-in-depth, no code changes
- **Cons:** Some directives may conflict with browser launch
- **Complexity:** Low

**Solution B: seccomp-BPF syscall filter for daemon**
- Add `SystemCallFilter=` with a whitelist of syscalls the daemon actually uses
- **Pros:** Significantly reduces daemon attack surface
- **Cons:** Complex to maintain, may break on kernel updates
- **Complexity:** Medium

**Recommended approach:** Solution A immediately. Solution B requires profiling daemon syscall usage first.

#### H-2: Namespace Isolation

**Solution A: Mount namespace only**
- Create a mount namespace for the browser
- Bind-mount only required paths (`/usr`, browser profile dir, X11/Wayland socket, fonts)
- **Pros:** Significant filesystem isolation
- **Cons:** Complex to enumerate required paths, breaks with unusual desktop environments
- **Complexity:** Medium

**Solution B: Full namespace stack**
- Create mount, PID, network, and user namespaces
- **Pros:** Maximum isolation
- **Cons:** Breaks X11/Wayland, networking, D-Bus; extremely complex
- **Complexity:** Very High

**Solution C: Filesystem namespacing via chroot**
- Use `pivot_root` or `chroot` into a minimal filesystem for the browser
- **Pros:** Simpler than full mount namespace
- **Cons:** Requires maintaining a minimal rootfs, still complex
- **Complexity:** High

**Recommended approach:** Solution A with a configurable allowlist of bind mounts. Start with a minimal set and expand based on testing.

#### H-3: seccomp-BPF

**Solution A: Blacklist dangerous syscalls**
- Block `ptrace`, `mount`, `umount`, `pivot_root`, `init_module`, `finit_module`, `kexec_load`, `bpf`, `perf_event_open`, etc.
- **Pros:** Simple, low risk of breaking Chromium
- **Cons:** Blacklists are inherently incomplete
- **Complexity:** Low

**Solution B: Whitelist based on Chromium's own filter**
- Use Chromium's seccomp-BPF policy as a baseline
- Adapt for the daemon's specific needs
- **Pros:** Well-tested policy, Chromium-compatible
- **Cons:** Chromium's policy is complex and version-dependent
- **Complexity:** Medium

**Solution C: libseccomp with architecture-specific profiles**
- Use `libseccomp` to generate architecture-specific BPF filters
- Different profiles for browser vs. principal processes
- **Pros:** Most robust, architecture-aware
- **Cons:** Requires `libseccomp` dependency, complex maintenance
- **Complexity:** High

**Recommended approach:** Solution A immediately (block obviously dangerous syscalls), then Solution B for the browser process specifically.

---

### Priority 2: Authorization Model

#### C-3: Self-Approval of Grants

**Solution A: Split approval into a separate code path with explicit audit**
- Replace `admin_authority()` with a `BrowserApprovalAuthority` that requires:
  - The principal's process identity digest
  - The endpoint's security config
  - A timestamp
  - A cryptographic binding to the request
- Log the approval with all context for post-hoc audit
- **Pros:** Maintains current flow, adds auditability
- **Cons:** Still self-approval, just better-documented
- **Complexity:** Low

**Solution B: Require human approval for grant activation**
- Before approving a grant, show a desktop notification asking the user to approve
- Wait for explicit user action (approve/deny)
- **Pros:** True human-in-the-loop
- **Cons:** Adds latency to every browser launch, notification injection risk (H-1)
- **Complexity:** Medium

**Solution C: Time-limited auto-approval with anomaly detection**
- Auto-approve grants but with strict time limits
- Track approval patterns and flag anomalies
- Require re-verification if patterns change (new RP, new credential, unusual timing)
- **Pros:** Balances security and usability
- **Cons:** Complex state machine, false positives
- **Complexity:** High

**Recommended approach:** Solution A immediately (auditability), then Solution B for high-security profiles (configurable per-profile).

#### H-1: D-Bus Notification Action Injection

**Solution A: Use a dedicated D-Bus service with restricted policy**
- Register a dedicated D-Bus well-known name for passless notifications
- Install a D-Bus policy file that restricts `ActionInvoked` signals to the notification server's bus name
- **Pros:** Prevents synthetic signal injection
- **Cons:** Requires D-Bus policy file installation, may not work with all notification servers
- **Complexity:** Medium

**Solution B: Use a separate notification channel**
- Replace D-Bus notifications with a direct terminal prompt or a custom GUI dialog
- **Pros:** No D-Bus attack surface
- **Cons:** Breaks headless operation, requires terminal or GUI access
- **Complexity:** Medium

**Solution C: Challenge-response verification**
- Generate a random challenge code displayed in the notification
- Require the user to enter the code in a separate channel (e.g., terminal, web interface)
- **Pros:** Prevents automated injection, proves human presence
- **Cons:** Significant UX impact, requires a second channel
- **Complexity:** High

**Solution D: Verify notification server identity**
- Check the D-Bus sender of `ActionInvoked` matches the notification server's bus name
- Reject actions from other senders
- **Pros:** Minimal change, directly addresses the attack
- **Cons:** Some notification servers may not forward sender information correctly
- **Complexity:** Low

**Recommended approach:** Solution D immediately (verify sender), then Solution A for defense-in-depth.

---

## Implementation Plan

### Phase 1: Quick Wins (Immediate)

These changes are low-risk, high-impact, and can be implemented without architectural changes:

| Issue | Action | Files | Risk |
|-------|--------|-------|------|
| C-1 | Apply selective hardening in same-user mode (close_range, setsid, PDEATHSIG, rlimits) | `browser.rs:2020-2034` | Low |
| C-2 | Add missing systemd hardening directives | `passless-agent.service` | Low |
| H-3 | Add seccomp-BPF blacklist for obviously dangerous syscalls | `launcher.rs:690-756` | Low |
| H-1 | Verify D-Bus signal sender matches notification server | `prompt.rs:627-633` | Low |
| C-3 | Add structured audit logging for grant self-approval | `browser_ensure.rs:398-409` | Low |

### Phase 2: Medium-Term (Requires Design Work)

These changes require design decisions, testing infrastructure, and careful rollout:

| Issue | Action | Dependencies |
|-------|--------|-------------|
| C-1 | Remove NNP bypass, rely on Chromium's user namespace sandbox | System compatibility testing |
| H-3 | Implement Chromium-specific seccomp-BPF whitelist | Syscall profiling |
| H-1 | Install D-Bus policy file for notification sender restriction | Packaging changes |
| C-3 | Implement per-profile approval policy (auto vs. human) | Policy engine extension |

### Phase 3: Long-Term (Architectural Changes)

These changes require significant architectural work and may affect backward compatibility:

| Issue | Action | Dependencies |
|-------|--------|-------------|
| H-2 | Implement mount namespace isolation for browser | Filesystem allowlist design |
| H-2 | Implement PID namespace isolation | Process lifecycle redesign |
| C-2 | Evaluate running daemon as non-root with capability dropping | UHID access model redesign |
| C-3 | Implement external approval mechanism (hardware token, separate service) | Protocol design |

---

## Testing Strategy

### Verification Tests

1. **FD leakage test:** After browser launch, verify `/proc/<browser_pid>/fd/` contains only expected FDs (stdin, stdout, stderr, CDP pipes). Assert no `/dev/uhid`, no storage file handles.

2. **Namespace verification test:** After browser launch, verify `/proc/<browser_pid>/ns/` shows expected namespace inodes. For mount namespace: verify the browser cannot access daemon-only paths.

3. **seccomp verification test:** After browser launch, verify `/proc/<browser_pid>/status` shows `Seccomp: 2` (SECCOMP_MODE_FILTER). Attempt blocked syscalls and verify they return `EPERM` or are killed.

4. **Systemd hardening test:** Run `systemd-analyze security passless-agent.service` and verify the exposure score improves. Target: < 5.0 (currently likely > 6.0 due to root + NoNewPrivileges=false).

5. **D-Bus sender verification test:** Attempt to inject a synthetic `ActionInvoked` signal from a test process. Verify the agent rejects it.

6. **Grant audit test:** Verify that every grant approval is logged with: request ID, principal digest, endpoint ID, RP IDs, credentials, timestamp, and approval authority token.

### Regression Testing

- **Browser launch compatibility:** Test browser launch on:
  - Systems with unprivileged user namespaces enabled (default on most distros)
  - Systems with user namespaces disabled (Debian with `sysctl kernel.unprivileged_userns_clone=0`)
  - Systems with AppArmor user namespace restrictions (Ubuntu 23.10+)
  - Systems without user namespace support (older kernels)

- **Notification compatibility:** Test notification flow with:
  - dunst
  - mako
  - notify-osd
  - xfce4-notifyd
  - GNOME Shell notification daemon

### Performance Benchmarking

- Measure browser launch latency with and without namespace isolation
- Measure seccomp-BPF overhead on CDP pipe I/O
- Measure FD close_range overhead on daemon with many open handles

---

## Risks and Mitigations

### Backward Compatibility

| Change | Risk | Mitigation |
|--------|------|-----------|
| Remove NNP bypass | Browser fails to start on systems without user namespaces | Feature detection: check `/proc/sys/kernel/unprivileged_userns_clone` before removing bypass. Fall back to current behavior if unavailable. |
| Mount namespace | Browser cannot find fonts, themes, X11 socket | Configurable bind-mount allowlist with sensible defaults. Test against major desktop environments. |
| seccomp-BPF | Chromium feature breaks (GPU, audio, DRM) | Start with blacklist (low risk). Use Chromium's own seccomp policy as reference. Provide escape hatch for testing. |
| D-Bus sender check | Notification server doesn't forward sender info | Log warning and fall back to current behavior if sender cannot be verified. |

### Migration Path

1. All Phase 1 changes are backward-compatible (additive hardening)
2. Phase 2 changes should be opt-in via configuration flags initially
3. Phase 3 changes require a deprecation period with clear migration documentation

### What Could Go Wrong

1. **Chromium sandbox breakage:** The most significant risk. Chromium's sandbox initialization is complex and version-dependent. Any change to the process environment (namespaces, seccomp, NNP) can break it.
   - **Mitigation:** Extensive testing across Chromium versions. Fallback to current behavior if sandbox initialization fails (detectable via CDP timeout).

2. **Desktop environment fragmentation:** Linux desktop environments vary widely in notification server implementation, D-Bus policy, and namespace support.
   - **Mitigation:** Configuration-driven approach with sensible defaults. Document tested configurations.

3. **Performance regression:** Namespace creation, seccomp-BPF, and FD closing add latency to browser launch.
   - **Mitigation:** Benchmark before and after. Target: < 100ms additional latency.

---

## Dependencies Between Issues

```
C-1 (same-user hardening)
  ├── H-3 (seccomp-BPF) — seccomp should be applied in same-user mode too
  └── H-2 (namespace isolation) — namespaces provide additional isolation beyond hardening

C-2 (systemd hardening)
  └── Independent — can be implemented in parallel

C-3 (self-approval)
  └── H-1 (D-Bus injection) — if human approval is added to C-3, H-1 becomes critical
                                because the approval notification becomes the attack target

H-1 (D-Bus injection)
  └── C-3 (self-approval) — if grants require human approval, the notification
                             channel becomes the primary attack surface
```

**Recommended implementation order:**

1. C-2 (systemd hardening) — zero code risk, immediate defense-in-depth
2. C-1 + H-3 (selective hardening + seccomp blacklist) — close FD leakage and block dangerous syscalls
3. H-1 (D-Bus sender verification) — prevent notification injection
4. C-3 (grant audit logging) — improve observability
5. C-1 (remove NNP bypass) — requires Chromium compatibility testing
6. H-2 (namespace isolation) — requires significant design work
7. C-3 (external approval) — requires protocol design

---

## References

### Code References

| Issue | Primary File | Key Lines |
|-------|-------------|-----------|
| C-1 | `cmd/passless/src/agent/browser.rs` | 1998-2035 (same-user bypass), 302-313 (hardening config) |
| C-2 | `contrib/systemd/passless-agent.service` | 37 (NoNewPrivileges), 42 (PrivateDevices) |
| H-2 | `cmd/passless/src/agent/browser.rs` | 1869-1912 (hardened spawn), 2000-2035 (port mode spawn) |
| H-3 | `cmd/passless/src/agent/launcher.rs` | 690-756 (apply method), 646-656 (HardenedChildSetup) |
| C-3 | `cmd/passless/src/agent/runtime/browser_ensure.rs` | 398-409 (self-approval) |
| C-3 | `cmd/passless/src/agent/intent.rs` | 212-230 (AdminAuthority) |
| C-3 | `cmd/passless/src/agent/policy_engine.rs` | 1426-1462 (grant request/approve) |
| H-1 | `cmd/passless/src/agent/prompt.rs` | 606-633 (notification), 479-499 (server capability) |

### Related Security Research

- **Chromium sandboxing:** https://chromium.googlesource.com/chromium/src/+/main/docs/linux/sandboxing.md
- **seccomp-BPF:** https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
- **Linux namespaces:** https://man7.org/linux/man-pages/man7/namespaces.7.html
- **D-Bus security:** https://dbus.freedesktop.org/doc/dbus-specification.html#auth-mechanisms
- **Desktop Notifications Specification:** https://specifications.freedesktop.org/notification-spec/latest/

### Similar Implementations

- **Firejail:** https://github.com/netblue30/firejail — Application sandboxing using namespaces, seccomp, and capabilities
- **Flatpak:** https://github.com/flatpak/flatpak — Application sandboxing with Bubblewrap (unprivileged namespaces)
- **Bubblewrap:** https://github.com/containers/bubblewrap — Unprivileged sandboxing tool (used by Flatpak)
- **systemd service hardening:** https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Sandboxing

---

## Open Questions

1. **Chromium user namespace compatibility:** What is the minimum Chromium version that reliably falls back to user namespace sandboxing? Can we detect sandbox initialization failure and fall back gracefully?

2. **Daemon non-root operation:** Can the daemon be restructured to drop root after UHID endpoint creation? This would eliminate the need for `NoNewPrivileges=false` and significantly reduce the impact of daemon compromise. What UHID operations require root beyond initial device creation?

3. **Grant approval model:** Should the approval model be per-profile configurable? Some profiles (e.g., development/testing) may want auto-approval, while production profiles should require human interaction. What is the right granularity?

4. **Notification channel replacement:** Is there a viable alternative to D-Bus notifications that works across all Linux desktop environments? A custom GUI dialog (GTK/Qt) would avoid D-Bus but adds dependencies. A terminal prompt would break headless operation.

5. **Namespace isolation scope:** For mount namespace isolation, what is the minimum set of paths that must be bind-mounted for Chromium to function? This varies by desktop environment (X11 vs Wayland, GNOME vs KDE vs Sway). Can we auto-detect the required paths?

6. **seccomp-BPF maintenance:** How do we maintain a seccomp-BPF whitelist across Chromium versions? Chromium's own sandbox policy changes with each release. Do we vendor Chromium's policy, or do we maintain our own?

7. **D-Bus policy distribution:** How do we distribute a D-Bus policy file that restricts `ActionInvoked` signals? This requires installation in `/etc/dbus-1/system.d/` or `/usr/share/dbus-1/services/`, which varies by distribution.

8. **Audit log integrity:** If the daemon is compromised, audit logs are also compromised. Should audit logs be sent to an external collector (e.g., journald, syslog, remote SIEM) for tamper resistance?
