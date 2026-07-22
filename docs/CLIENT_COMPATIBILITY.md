# Client Compatibility and Troubleshooting

This document explains how WebAuthn requests reach Passless, what can fail at each layer, and how
to diagnose client-specific compatibility issues. It covers Electron applications, Flatpak/Snap
packages, and the emerging `credentialsd` architecture.

## How a WebAuthn Request Reaches Passless

A WebAuthn operation crosses several independent boundaries:

```
Relying-party web application
    ↓
WebAuthn implementation in browser/Electron
    ↓
Client-side WebAuthn UI and policy
    ↓
FIDO HID discovery and permissions
    ↓
CTAP2 request over HID transport
    ↓
Passless daemon
    ↓
Passless storage and user verification
```

### WebAuthn vs CTAP2

- **WebAuthn** is the browser/application API that websites use.
- **CTAP2** is the protocol spoken between the browser/application and the FIDO authenticator over
  HID transport.

Passless implements CTAP2. The browser or application implements WebAuthn and translates it to CTAP2.

### UHID Producer vs HIDRAW Consumer

Passless and the WebAuthn client access different devices:

- **Passless** opens `/dev/uhid` to create a virtual FIDO HID authenticator.
- **WebAuthn client** (browser, Electron app, etc.) opens the generated `/dev/hidraw*` device to
  send CTAP2 requests.

A successful Passless daemon start only proves that the lower part of the chain is available. It
does not guarantee that every browser, Electron application, or confined package can complete every
WebAuthn ceremony.

### Browser/Application Responsibilities

The browser or application is responsible for:

- Discovering the FIDO HID device.
- Implementing WebAuthn mediation (origin validation, RP ID checks).
- Providing user verification UI (PIN entry, account selection).
- Sending CTAP2 requests and processing responses.

If any of these layers fail, the WebAuthn ceremony fails before Passless receives a CTAP request.

## Compatibility Boundaries

Several independent boundaries can affect WebAuthn compatibility:

### 1. Browser WebAuthn Implementation

Different browsers have different levels of WebAuthn support:

- **Chromium-based browsers** (Chrome, Edge, Brave, Vivaldi) generally have mature WebAuthn support.
- **Firefox** has its own WebAuthn implementation with different behavior.
- **Older browser versions** may lack support for resident credentials, conditional UI, or other
  FIDO2 features.

### 2. Electron Version and Application Integration

Electron applications bundle a specific Chromium version. WebAuthn behavior depends on:

- The Electron version (older versions may have incomplete WebAuthn mediation).
- Whether the application has implemented WebAuthn support or relies on Chromium's default.
- Application-specific policy or capability detection.

### 3. Flatpak/Snap Confinement

Flatpak and Snap packages may restrict:

- Device access (the application cannot open `/dev/hidraw*`).
- D-Bus access (the application cannot communicate with system services).
- Portal access (the application cannot use desktop portals for credential selection).

This is separate from Electron's renderer sandbox (see below).

### 4. FIDO HID Permissions

The WebAuthn client must have read/write access to the generated `/dev/hidraw*` device. This is
typically controlled by udev rules and group membership (e.g., the `fido` group).

### 5. PIN, UV, Resident Credentials, and Account-Selection UI

Even if the CTAP2 request reaches Passless, the ceremony can fail if:

- The client does not support PIN entry or user verification UI.
- The client does not support resident credential selection.
- The client applies policy that rejects the credential (e.g., attestation requirements).

## Electron Applications

### Renderer Sandbox vs Device Confinement

Electron's `webPreferences.sandbox: true` primarily applies to the **renderer process**. WebAuthn
and FIDO transport work is normally brokered by browser-side Chromium/Electron code, not the
renderer.

Therefore, the renderer sandbox alone should not be presented as proof that HID access is blocked.
Device confinement is a separate concern, typically controlled by OS-level permissions (udev,
Flatpak/Snap policies, etc.).

### Reported Compatibility Issues

A compatibility report in [discussion #294](https://github.com/pando85/passless/discussions/294)
describes passkey registration failing in Vesktop while the same Discord flow works in a regular
browser.

This is a useful data point, but it does not prove:

- That Electron's renderer sandbox is responsible.
- That Passless cannot have an interoperability edge case.
- That the same behavior applies to every Electron version or package.
- That `credentialsd` will solve it without explicit client integration.

The failure is most likely a **client-specific WebAuthn or confinement issue**, but the exact
boundary requires further investigation.

### Testing Electron Applications

When troubleshooting an Electron application:

1. **Test the same relying party in a native browser** (Chrome, Firefox). If it works, the issue is
   specific to the Electron application.

2. **Test a minimal Electron application** with the same Electron version. If it also fails, the
   issue is likely in the Electron version or system configuration.

3. **Check the Electron version** (`process.versions.electron` in the main process). Compare with
   the latest stable release.

4. **Check application logs** for WebAuthn errors or CTAP failures.

5. **Do not recommend `--no-sandbox` as a permanent workaround.** Disabling the renderer sandbox
   reduces security. It should only be used for debugging, not as a production fix.

## Flatpak and Snap Packages

### Package Confinement May Affect FIDO Access

Flatpak and Snap packages may restrict the browser-side process from discovering or opening a FIDO
HID device. This is separate from Electron's renderer sandbox.

### Comparing Package Formats

When troubleshooting a Flatpak or Snap package:

1. **Test the native package** (`.deb`, `.rpm`, AppImage, or upstream tarball). If it works, the
   issue is specific to the confined package.

2. **Test a different confined package** (e.g., if Flatpak fails, try Snap). If both fail, the
   issue may be in the application's WebAuthn implementation.

3. **Check package permissions** (Flatpak: `flatpak info --show-permissions <app>`, Snap:
   `snap connections <app>`). Look for device access, D-Bus access, or portal access.

4. **Avoid publishing broad package-specific commands** unless tested and maintained. Permissions
   and policies change between package versions.

## Credentials for Linux / credentialsd

### Goal: OS-Level Credential Broker

[`credentialsd`](https://github.com/linux-credentials/credentialsd) aims to provide a Linux
OS-level credential API analogous to Windows Hello, Apple Keychain, and Android Credential Manager.

Its intended architecture:

```
Browser or application
    ↓
credentialsd Gateway over D-Bus/portal-style API
    ↓
Origin and RP-ID validation
    ↓
Shared WebAuthn UI and flow control
    ↓
FIDO authenticator/provider selection
    ↓
CTAP2 over HID or a native credential provider
```

### Existing HID-Authenticator Path

Passless can participate in `credentialsd` as an ordinary FIDO2 HID authenticator:

```
Browser/Electron integration
    ↓
credentialsd
    ↓
credentialsd USB/FIDO handler
    ↓
Passless virtual FIDO HID device
```

This path could move device discovery, PIN/UV handling, account selection, and CTAP interaction out
of an Electron application and into the trusted desktop credential service.

**However:** Installing `credentialsd` by itself does not transparently redirect an arbitrary
application's `navigator.credentials` calls. The browser or application must explicitly integrate
with the `credentialsd` Gateway.

### Future Native Provider Path

A future Passless provider could avoid UHID and hidraw entirely and present Passless as a Linux
platform authenticator:

```
Browser/application
    ↓
credentialsd
    ↓
Passless credential provider
    ↓
pass / TPM / local Passless storage backend
```

This is a possible roadmap item, not current functionality.

### Current Integration Status

Current `credentialsd` integrations are **experimental and client-specific**. They do not
automatically enable arbitrary Electron, Flatpak, or Snap applications.

To test `credentialsd` integration:

1. Ensure the browser or application actually routes its WebAuthn request through the
   `credentialsd` Gateway (not just installed alongside it).
2. Check `credentialsd` logs for authenticator discovery and CTAP requests.
3. Verify that the browser/application is using the `credentialsd` API, not direct HID access.

## Diagnostic Procedure

Follow this ordered procedure rather than treating every failure as a permissions problem.

### Step 1: Verify Passless Itself

```bash
systemctl --user status passless
journalctl --user -u passless -n 100
```

Confirm that Passless started successfully and created the virtual authenticator.

### Step 2: Test in a Regular Native Browser

Try the same relying party or a neutral WebAuthn test site (e.g., `https://webauthn.io`) in a
natively installed browser (Chrome, Firefox).

**Interpretation:**

- **Browser and application both fail:** Investigate Passless, HID exposure, permissions, and CTAP
  compatibility.
- **Browser works but Electron/application fails:** Investigate the client, its Electron version,
  WebAuthn mediation, or package confinement.

### Step 3: Observe Whether Passless Receives CTAP Traffic

Run:

```bash
journalctl --user -u passless -f
```

Then initiate the ceremony.

- **No CTAP request reaches Passless:** Failure is upstream of Passless (browser/application
  issue).
- **CTAP request reaches Passless and returns an error:** Capture the operation and status before
  classifying the problem.

### Step 4: Compare a Physical FIDO2 Key

- **Physical key also fails in the affected application:** Likely client/WebAuthn/application
  behavior.
- **Physical key works but Passless fails:** Investigate virtual HID discovery or CTAP
  interoperability.

### Step 5: Compare Packaging

Record and compare:

- Native package (`.deb`, `.rpm`, AppImage, tarball).
- Flatpak.
- Snap.

Keep the Electron/application version constant when possible.

### Step 6: Record the WebAuthn Exception

Capture the actual JavaScript error, including its name:

- `NotAllowedError` — user cancelled or denied.
- `NotSupportedError` — unsupported algorithm or option.
- `SecurityError` — origin or security policy violation.
- `InvalidStateError` — credential already exists or invalid state.
- Timeout or cancellation — no response from authenticator.

Also capture relevant Electron/Chromium logs if available.

### Step 7: Test credentialsd Only as an Explicit Integration

Do not present `credentialsd` as a transparent daemon-side fix. A valid test must establish that the
browser, extension, patched client, or application is actually routing its WebAuthn request through
the `credentialsd` Gateway.

## Compatibility Report Template

Use this template when reporting a compatibility issue:

```markdown
### Client
- Application:
- Application version:
- Electron/Chromium version:
- Installation format: native / AppImage / Flatpak / Snap / other
- Distribution:
- Kernel:
- Display server: Wayland / X11

### Passless
- Passless version:
- Storage backend:
- PIN policy:
- `always_uv`:
- User-verification method:

### WebAuthn operation
- Relying party or test site:
- Registration or authentication:
- Resident/discoverable credential requested:
- User verification requirement:
- Attestation preference:
- JavaScript exception:

### Results
- Works in native browser:
- Works with physical FIDO2 key in affected application:
- Passless receives a CTAP request:
- Relevant Passless logs:
- Native package versus Flatpak/Snap result:
- credentialsd integration used, if any:
```

## Security Considerations

### Do Not Disable Application Sandboxing

The documentation must not suggest disabling Electron/Chromium sandboxing as a production fix. An
Electron application rendering remote content should preserve renderer sandboxing and context
isolation.

### Future credentialsd Integration Security

Any future Electron or Vesktop bridge to `credentialsd` must bind the claimed WebAuthn origin and
RP ID to the trusted `WebContents`/frame context. The remote renderer must not be able to supply an
arbitrary origin over IPC.

### Portal-Style Broker Trust Boundary

A portal-style broker changes the trust boundary: it can protect device access and centralize
policy, but only if callers are authenticated and origins are validated.
