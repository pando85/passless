# Environment spikes Q4, Q5, Q7, Q8, Q9 (2026-11-10)

Scripts are in `env/`. All hermetic: scratch dir `$SPIKE_SCRATCH` (default `<scratchpad>/envspike`), temp user-data-dirs,
private `dbus-run-session`, no privilege escalation. `lib.js` loads `playwright-core` from the earlier spike dir via `createRequire`
(override with `PW_FROM`). Browsers: Chromium 156.0.8078.79 (Arch), Google Chrome 157.0.8103.38, Chrome for Testing 157.0.8103.50.
Probe convention: a WebAuthn call still pending after N s means the browser accepted it; a SecurityError/other rejection is immediate.

## Q4. `--ignore-certificate-errors-spki-list` and WebAuthn on `https://rp-a.test`: YES

Reproduce: `xvfb-run -a node env/q4-spki-webauthn.js` (self-signed cert for rp-a.test made by openssl, https on :18443,
`--host-resolver-rules="MAP rp-a.test 127.0.0.1" --ignore-certificate-errors-spki-list=<b64 sha256 SPKI>`).

```
[headed   spki-list] https://rp-a.test:18443 loaded status 200
[headed   spki-list]  create rpId=rp-a.test: PENDING (accepted by browser, no authenticator answered)
[headed   spki-list]  get    rpId=rp-a.test: PENDING (accepted ...)
[headless spki-list] (same results)
[headed   no-cert-flag] https://rp-a.test:18443 NAV FAIL net::ERR_CERT_AUTHORITY_INVALID
[headed   ignore-all]   (--ignore-certificate-errors) loaded 200; create/get PENDING (accepted)
```
- No cert-error rejection of WebAuthn was observed: with the SPKI flag (and with blanket `--ignore-certificate-errors`) the page loads
  and create/get are accepted. Without any flag the navigation itself fails, so WebAuthn never runs. The "page loads but WebAuthn
  rejects because of a cert error" case did not occur (the `AllowWebAuthnWithBrokenTlsCerts` policy string exists in the binary, but
  was not needed). So no error text exists to report.
- `http://localhost:18080` with rpId `localhost`: accepted (pending), headed and headless.
- `http://rp-a.localhost:18080` with rpId `rp-a.localhost`: accepted (pending), headed and headless (no resolver rule needed).
- `http://rp-a.test:18080` (plain http, non-localhost): `navigator.credentials` is `undefined` (insecure context), as expected.

## Q5. Chrome for Testing / other browsers: CfT loads the extension (headed and new headless); branded Chrome and headless-shell do not

Reproduce: `npx @puppeteer/browsers install chrome@stable --path $SPIKE_SCRATCH/cft` (also `chrome-headless-shell@stable`),
then `xvfb-run -a node env/q5-browser-matrix.js`. Probe extension: `env/ext-min` (MV3 service worker plus a content script that
sets an attribute on `http://localhost/*`). Decisive signal = content script injected.

```
chromium 156 (distro)   headed | headless=new : content-script-injected=true   (with and without --disable-extensions-except)
chrome-for-testing 157  headed | headless=new : content-script-injected=true   (with and without --disable-extensions-except)
chrome-stable 157 (branded) headed | headless=new : content-script-injected=false (service-worker target count identical, flag ignored)
chrome-headless-shell 157 (CfT)               : sw-targets=0, content-script-injected=false
microsoft-edge, brave, brave-browser          : NOT INSTALLED, skipped
```
Detection of CfT: `chrome --version` prints `Google Chrome for Testing 157.0.8103.50`
(branded: `Google Chrome 157.0.8103.38`; distro: `Chromium 156.0.8078.79 Arch Linux`).
CDP `Browser.getVersion` product and the UA are `Chrome/157.0.8103.50` and do NOT say "for Testing" (headless: `HeadlessChrome/157...`),
so detection must use `--version` output or the install path, not the UA. CfT installs ~ `chrome/linux-157.0.8103.50/chrome-linux64/chrome`.

## Q7. Chromium switch / feature / policy that disables the HID security-key transport: NO

Reproduce: `env/passless-test-instance.sh start`; `xvfb-run -a node env/q7-hid-transport.js`; `xvfb-run -a node env/q7-strace.js`;
`env/passless-test-instance.sh stop`. Verdict is the number of `*.bin` credential files in the test passless store
(other agents' passless instances can be present, so page success alone is not proof).

Baseline (no extension, Chromium 156, headed and headless): `navigator.credentials.create` on `http://localhost` succeeds, store 2->3,
3->4. `strace -f -e trace=openat`: `openat(AT_FDCWD, "/dev/hidraw6", O_RDWR) = 117` (only the passless UHID node; hidraw0-4 are root-only and not opened).
So an un-intercepted request does reach the HID authenticator. Candidates tested (each headed and headless):

| Candidate | Result |
|---|---|
| `--disable-features=SecurityKeyHidInterfacesAreFido` | still created, store grows |
| `--disable-blink-features=WebAuth` | `PublicKeyCredential` becomes undefined, but `navigator.credentials.create({publicKey})` STILL created a credential via HID (store grows) |
| `--disable-features=WebAuthentication,WebAuthenticationAPI,WebAuthenticationPasskeyUpgrade` (guessed names) | still created |
| `LD_LIBRARY_PATH` stub `libudev.so.1` | Chromium refuses to start (libudev is linked, not dlopened); not usable |
| CDP `WebAuthn.enable` + `addVirtualAuthenticator` | request goes to the virtual authenticator, store unchanged (10 -> 10). Not a disable: it lives only while that CDP session does, any CDP client can remove it, and it takes precedence over the webAuthenticationProxy extension. Also `WebAuthn.disable` afterwards did not restore HID (store unchanged) |
| managed policy | binary strings list only SecurityKeyPermitAttestation, WebAuthenticationRemoteProxiedRequestsAllowed, WebAuthenticationAmbient* and similar; none disables CTAP-over-HID (WebHid* policies are WebHID only). Could not install a policy (no root); not tested |

No switch, feature or policy found. `--disable-hid-blocklist` and `HidBlockedForUrls` concern WebHID, not FIDO. Containment must be
filesystem/uid based (see Q8).

## Q8. bwrap private /dev hides hidraw and Chromium still runs: YES

bubblewrap 0.13.0 at `/usr/bin/bwrap`; `unshare -U true` works (unprivileged user namespaces available, `max_user_namespaces=256206`).
Minimal working argv (no extra flags needed; `/dev/shm` is provided by `--dev`):

```
bwrap --dev-bind / / --dev /dev --die-with-parent  <chromium> ...
```
Private /dev contains: `core fd full null ptmx pts random shm stderr stdin stdout tty urandom zero`; no `hidraw*`, no `uhid`.
Reproduce: `env/passless-test-instance.sh start; xvfb-run -a node env/q8-bwrap.js`.
```
bwrap headed        : create PENDING (never answered), store 12 -> 12
bwrap headless=new  : create PENDING, store 12 -> 12
no bwrap (control)  : create succeeds, store 12 -> 13
strace inside bwrap : zero /dev/hidraw openat calls
```
- Chromium's own sandbox is still active inside bwrap, with no `--no-sandbox`: browser `NoNewPrivs=1`; renderers have a different
  user namespace and pid namespace than the browser, and renderer/utility processes show `Seccomp=2`. (The setuid chrome-sandbox is
  not used; the userns sandbox works nested inside bwrap's userns.)
- Side effects: supplementary groups are dropped in bwrap (`groups=1000(agil),65534(nobody)`; `fido` is lost, which is fine), uid stays 1000.
  `/sys/class/hidraw` remains visible but the device nodes do not exist, so opening fails or is never attempted.
- Caveat: `--dev /dev` hides the host `/dev/shm`, so anything shared through `/dev/shm` with the host (for example a cargo target dir)
  is not visible inside. Add `--bind /dev/shm /dev/shm` only if required, which does not expose hidraw. Needs xvfb socket access
  for headed (`/tmp/.X11-unix` is visible via `--dev-bind / /`).

## Q9. Root dropping to the user can use the user session bus: YES if the drop is a real setresuid/setgid before connect; no if root connects as itself

Verified (unprivileged, `env/q9-dbus-userns.sh`, private bus via dbus-run-session):
```
plain uid 1000 client                                 : GetConnectionUnixUser -> 1000
client in `unshare -r` (ns uid 0, kernel uid 1000)    : bus sees uid 1000 (peer creds are the kernel uid, translated into the daemon's namespace)
raw EXTERNAL claiming uid 1000 (matches creds)        : OK <guid>
raw EXTERNAL claiming uid 0 or 1 (not the creds)      : REJECTED EXTERNAL
libdbus (dbus-send) inside `unshare -r` (claims ns uid 0): no reply (auth rejected)
```
So EXTERNAL auth needs claimed uid == SO_PEERCRED uid, and the credential is the kernel uid at connect time.

Reasoned from dbus 1.16.2 source (fetched from sources.debian.org, not run as root):
- `dbus-auth.c`: authenticates only if the socket credentials are a superset of the claimed identity.
- `bus/policy.c: bus_policy_allow_unix_user`: default `allowed = _dbus_unix_user_is_process_owner(uid)` (uid == bus daemon euid); only
  `<allow user=...>` rules extend it, and `/usr/share/dbus-1/session.conf` has none (0 matches). `auth_via_default_rules` (root OK) is
  not used because the daemon installs a unix-user function. So a root process connecting as uid 0 is REJECTED by dbus-daemon; after
  `setresgid(g,g,g); setgroups(0,NULL); setresuid(u,u,u)` (and `getuid()==u` so libdbus/zbus claim the right uid) it matches the bus owner and
  is accepted. `/run/user/<uid>/bus` is mode 0666 and `/run/user/<uid>` is 0700 owned by the user, so after the drop the owner can traverse it.
- Not verified: the user's real session bus here is `dbus-broker`, not dbus-daemon; its policy for uid 0 was not checked. The drop approach
  does not depend on it. Never tested with a real root process (not possible here).

Recommended helper design: a separate short-lived child process (fork+exec of a small helper) that does
`setgroups(0)`, `setresgid`, `setresuid` to the target user (check with `getresuid`/`getresgid`, set `PR_SET_NO_NEW_PRIVS`, drop all caps),
then connects to `unix:path=/run/user/<uid>/bus`, performs the single D-Bus operation and exits. Not in-process: `setresuid` is process-wide
and irreversible for the privileged daemon (all threads of a tokio runtime would lose root), and an in-process thread-level drop
(`syscall(SYS_setresuid)` per thread) is fragile with libc/zbus helper threads and leaves the process's saved ids to be audited.
