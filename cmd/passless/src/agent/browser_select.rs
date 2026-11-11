//! Which browser binary the daemon runs for a managed browser, and which it refuses (ADR 0014
//! section 4.2 and plan D4, R14).
//!
//! Supported: Chromium and Chrome for Testing (Playwright's Chromium is Chrome for Testing).
//! Refused, with an actionable message:
//!
//! - branded Google Chrome: it ignores `--load-extension`, so the interception extension would not
//!   load and every WebAuthn request would reach the human authenticator;
//! - `chrome-headless-shell`: it loads no extensions. Its `--version` prints
//!   `Google Chrome for Testing <version>`, exactly like the full Chrome for Testing binary (probed
//!   on Playwright's `chromium_headless_shell-1247`, P10b), so it is recognised by binary name or
//!   install path only.
//!
//! Auto-detection order when nothing names a binary: `agents.browser_path`, Playwright's Chromium
//! in `~/.cache/ms-playwright`, Chrome for Testing in `~/.cache/puppeteer`, the distribution's
//! `chromium`. In a distinct-UID deployment (a root daemon and a principal with another UID) only
//! binaries owned by root, on a path nobody else can write, are accepted (V-H7): the principal
//! must not be able to replace the browser the daemon starts.

use std::fmt;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long `<browser> --version` may take.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// What a browser binary is, as far as passless can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserKind {
    Chromium,
    ChromeForTesting,
    /// Branded Google Chrome (stable, beta, dev): refused.
    BrandedChrome,
    /// `chrome-headless-shell`: refused.
    HeadlessShell,
    /// Anything else (Edge, Brave, a wrapper script, ...): never auto-detected; an explicit path
    /// to one is accepted with a warning, because it was not probed.
    Unknown,
}

impl BrowserKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Chromium => "Chromium",
            Self::ChromeForTesting => "Chrome for Testing",
            Self::BrandedChrome => "branded Google Chrome",
            Self::HeadlessShell => "chrome-headless-shell",
            Self::Unknown => "an unrecognised browser",
        }
    }

    pub fn is_supported(self) -> bool {
        matches!(self, Self::Chromium | Self::ChromeForTesting)
    }

    pub fn is_refused(self) -> bool {
        matches!(self, Self::BrandedChrome | Self::HeadlessShell)
    }
}

/// The kind a `--version` line says. It cannot tell `chrome-headless-shell` from Chrome for
/// Testing; [`kind_from_path`] covers that.
pub fn kind_from_version(version: &str) -> BrowserKind {
    let version = version.trim();
    if version.contains("Google Chrome for Testing") {
        return BrowserKind::ChromeForTesting;
    }
    // "Google Chrome 157.0..." and "Google Chrome Beta 158..." are branded; the Testing build was
    // handled above, so this prefix never matches it.
    if version.starts_with("Google Chrome") {
        return BrowserKind::BrandedChrome;
    }
    if version.starts_with("Chromium") {
        return BrowserKind::Chromium;
    }
    BrowserKind::Unknown
}

/// The refused kind a binary name or install path gives away, if any: `chrome-headless-shell`
/// (also Playwright's `headless_shell` and `chromium_headless_shell-<n>`), or a `google-chrome*`
/// binary. Judged on every component of the path, the symlink target included.
pub fn kind_from_path(path: &Path) -> Option<BrowserKind> {
    for component in path.components() {
        let name = component
            .as_os_str()
            .to_string_lossy()
            .to_ascii_lowercase()
            .replace('_', "-");
        if name.contains("headless-shell") {
            return Some(BrowserKind::HeadlessShell);
        }
    }
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if file.starts_with("google-chrome") {
        return Some(BrowserKind::BrandedChrome);
    }
    // /opt/google/chrome/chrome, /opt/google/chrome-beta/chrome
    let installed_by_google = path
        .parent()
        .and_then(Path::parent)
        .is_some_and(|dir| dir.ends_with("google"))
        || path.parent().is_some_and(|dir| {
            dir.to_string_lossy()
                .to_ascii_lowercase()
                .contains("/opt/google/chrome")
        });
    if file == "chrome" && installed_by_google {
        return Some(BrowserKind::BrandedChrome);
    }
    None
}

/// Why a binary was not accepted, with what to do about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserRejection {
    pub path: PathBuf,
    pub kind: BrowserKind,
    pub message: String,
}

impl fmt::Display for BrowserRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BrowserRejection {}

const INSTALL_HINT: &str = "install Playwright's Chromium (`npx playwright install chromium`, \
     which lands in ~/.cache/ms-playwright), Chrome for Testing (`npx @puppeteer/browsers install \
     chrome@stable`) or your distribution's `chromium`, and point agents.browser_path at it (or \
     remove agents.browser_path and the profile's browser_command to let passless detect it)";

fn refused_message(path: &Path, kind: BrowserKind, version: &str) -> String {
    match kind {
        BrowserKind::BrandedChrome => format!(
            "{} is branded Google Chrome ({}), which passless cannot use: it ignores \
             --load-extension, so the passless agent extension would not load and WebAuthn \
             requests would reach the human authenticator (ADR 0014 section 7). {INSTALL_HINT}",
            path.display(),
            version.trim()
        ),
        BrowserKind::HeadlessShell => format!(
            "{} is chrome-headless-shell, which passless cannot use: it loads no extensions, so \
             WebAuthn requests would not be intercepted (ADR 0014 section 7). Its --version \
             prints '{}', the same as the full Chrome for Testing, so it is recognised by name. \
             Use a full Chromium, which runs headless with --headless=new (the default): \
             {INSTALL_HINT}",
            path.display(),
            version.trim()
        ),
        _ => format!("{} is not a supported browser", path.display()),
    }
}

/// The trust required of a browser binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Shared-UID deployment: the binary is the daemon user's own.
    Any,
    /// Distinct-UID deployment (V-H7): the binary and every directory on its canonical path must
    /// be owned by root and writable by neither group nor others.
    RootOwned,
}

/// Runs `<exe> --version` and returns its first stdout line.
pub type VersionRunner<'a> = &'a dyn Fn(&Path) -> Result<String, String>;

/// The real `--version` run: no stdin, a minimal environment, 10 s.
pub fn run_version(exe: &Path) -> Result<String, String> {
    let mut child = Command::new(exe)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .spawn()
        .map_err(|e| format!("cannot run {} --version: {e}", exe.display()))?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stdout).take(8192).read_to_string(&mut text);
        let _ = tx.send(text);
    });
    let deadline = Instant::now() + VERSION_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(format!("{} --version failed ({status})", exe.display()));
                }
                break;
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} --version timed out", exe.display()));
            }
            Err(e) => return Err(format!("waiting for {} --version: {e}", exe.display())),
        }
    }
    let text = rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
    Ok(text.lines().next().unwrap_or("").trim().to_string())
}

/// Every component of the canonical `path`, the file included, is owned by root and writable by
/// neither group nor others (V-H7).
fn root_owned_path(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    for component in path.ancestors() {
        let meta = fs::symlink_metadata(component)
            .map_err(|e| format!("inspect {}: {e}", component.display()))?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(format!(
                "{} is owned by uid {} with mode {:o}",
                component.display(),
                meta.uid(),
                meta.mode() & 0o7777
            ));
        }
    }
    Ok(())
}

/// A browser binary that is accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserInfo {
    /// The canonical path (symlinks resolved) when it could be resolved, else the given path.
    pub path: PathBuf,
    pub kind: BrowserKind,
    pub version: String,
}

/// Judge one named binary: refuse branded Chrome and `chrome-headless-shell` (by path, then by
/// `--version`), apply the distinct-UID trust rule, and report what it is. An unrecognised
/// browser passes (an explicit choice); [`BrowserInfo::kind`] says so.
pub fn check_binary(
    path: &Path,
    trust: Trust,
    version_of: VersionRunner<'_>,
) -> Result<BrowserInfo, BrowserRejection> {
    let reject = |kind, message| BrowserRejection {
        path: path.to_path_buf(),
        kind,
        message,
    };
    let canonical = fs::canonicalize(path).map_err(|e| {
        reject(
            BrowserKind::Unknown,
            format!("browser binary {} is not usable: {e}", path.display()),
        )
    })?;
    let meta = fs::metadata(&canonical).map_err(|e| {
        reject(
            BrowserKind::Unknown,
            format!("browser binary {} is not usable: {e}", canonical.display()),
        )
    })?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err(reject(
            BrowserKind::Unknown,
            format!(
                "browser binary {} is not an executable file",
                canonical.display()
            ),
        ));
    }
    // By name first, on the path as given and as resolved (a `chromium` symlink to a headless
    // shell is still one), and before anything is executed.
    let by_path = kind_from_path(path).or_else(|| kind_from_path(&canonical));
    if trust == Trust::RootOwned
        && let Err(why) = root_owned_path(&canonical)
    {
        return Err(reject(
            by_path.unwrap_or(BrowserKind::Unknown),
            format!(
                "browser binary {} is not accepted for a distinct-UID principal: {why}. The \
                 principal must not be able to replace the browser the daemon starts, so the \
                 binary and every directory above it must be owned by root and not writable by \
                 others (install it system-wide, e.g. your distribution's chromium package, and \
                 set agents.browser_path)",
                canonical.display()
            ),
        ));
    }
    if let Some(kind) = by_path.filter(|k| k.is_refused()) {
        // The version string only enriches the message; a binary that will not run still refuses.
        let version = version_of(&canonical).unwrap_or_default();
        return Err(reject(kind, refused_message(path, kind, &version)));
    }
    let version = version_of(&canonical).map_err(|e| {
        reject(
            BrowserKind::Unknown,
            format!(
                "browser binary {} did not report a version: {e}",
                path.display()
            ),
        )
    })?;
    let kind = kind_from_version(&version);
    if kind.is_refused() {
        return Err(reject(kind, refused_message(path, kind, &version)));
    }
    Ok(BrowserInfo {
        path: canonical,
        kind,
        version,
    })
}

/// Where a detected browser came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Explicit,
    PlaywrightChromium,
    ChromeForTesting,
    DistroChromium,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::Explicit => "agents.browser_path",
            Self::PlaywrightChromium => "Playwright Chromium (~/.cache/ms-playwright)",
            Self::ChromeForTesting => "Chrome for Testing (~/.cache/puppeteer)",
            Self::DistroChromium => "the distribution's chromium",
        }
    }
}

/// Where auto-detection looks. Production values come from [`SearchRoots::for_home`]; tests inject
/// their own.
#[derive(Clone, Debug, Default)]
pub struct SearchRoots {
    /// Directories holding `chromium-<revision>/` (Playwright's browser cache).
    pub playwright: Vec<PathBuf>,
    /// Directories holding `chrome/linux-<version>/` (the `@puppeteer/browsers` cache).
    pub puppeteer: Vec<PathBuf>,
    /// Distribution binaries, in order.
    pub distro: Vec<PathBuf>,
}

impl SearchRoots {
    /// The standard locations for a user whose home directory is `home`, honouring
    /// `PLAYWRIGHT_BROWSERS_PATH` and `PUPPETEER_CACHE_DIR` when set in the daemon's environment.
    pub fn for_home(home: Option<&Path>) -> Self {
        let mut playwright = Vec::new();
        if let Some(dir) = std::env::var_os("PLAYWRIGHT_BROWSERS_PATH")
            .map(PathBuf::from)
            .filter(|dir| dir.is_absolute())
        {
            playwright.push(dir);
        }
        let mut puppeteer = Vec::new();
        if let Some(dir) = std::env::var_os("PUPPETEER_CACHE_DIR")
            .map(PathBuf::from)
            .filter(|dir| dir.is_absolute())
        {
            puppeteer.push(dir);
        }
        if let Some(home) = home {
            playwright.push(home.join(".cache/ms-playwright"));
            puppeteer.push(home.join(".cache/puppeteer"));
        }
        Self {
            playwright,
            puppeteer,
            distro: [
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
                "/usr/local/bin/chromium",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
        }
    }
}

/// `chromium-<revision>` directories of a Playwright cache, newest revision first.
fn playwright_candidates(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut revisions: Vec<(u64, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let revision = name.strip_prefix("chromium-")?.parse::<u64>().ok()?;
            Some((revision, entry.path()))
        })
        .collect();
    revisions.sort_by_key(|a| std::cmp::Reverse(a.0));
    revisions
        .into_iter()
        .flat_map(|(_, dir)| {
            ["chrome-linux64/chrome", "chrome-linux/chrome"]
                .iter()
                .map(move |rel| dir.join(rel))
        })
        .collect()
}

/// `chrome/linux-<version>/chrome-linux64/chrome` of a puppeteer cache, newest version first.
fn puppeteer_candidates(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root.join("chrome")) else {
        return Vec::new();
    };
    let mut versions: Vec<(Vec<u64>, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let version = name.strip_prefix("linux-")?;
            let key = version
                .split('.')
                .map(|part| part.parse::<u64>().ok())
                .collect::<Option<Vec<_>>>()?;
            Some((key, entry.path()))
        })
        .collect();
    versions.sort_by(|a, b| b.0.cmp(&a.0));
    versions
        .into_iter()
        .map(|(_, dir)| dir.join("chrome-linux64/chrome"))
        .collect()
}

/// No supported browser was found: what was looked at and why each candidate was passed over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionFailure {
    pub passed_over: Vec<String>,
}

impl fmt::Display for DetectionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no supported browser found (Chromium and Chrome for Testing are supported; looked in \
             Playwright's ~/.cache/ms-playwright, ~/.cache/puppeteer and the distribution's \
             chromium)"
        )?;
        for why in &self.passed_over {
            write!(f, "; {why}")?;
        }
        write!(f, ". {INSTALL_HINT}")
    }
}

impl std::error::Error for DetectionFailure {}

/// The first supported browser, in D4 order. Candidates that are refused or unusable are passed
/// over and reported if nothing is found. An explicit `browser_path` is judged alone: if it is
/// refused, the error is returned and nothing else is tried (a refused explicit choice must not
/// quietly turn into another browser).
pub fn detect(
    explicit: Option<&Path>,
    roots: &SearchRoots,
    trust: Trust,
    version_of: VersionRunner<'_>,
) -> Result<(BrowserInfo, Source), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(path) = explicit {
        let info = check_binary(path, trust, version_of)?;
        return Ok((info, Source::Explicit));
    }
    let mut passed_over = Vec::new();
    let groups: [(Source, Vec<PathBuf>); 3] = [
        (
            Source::PlaywrightChromium,
            roots
                .playwright
                .iter()
                .flat_map(|root| playwright_candidates(root))
                .collect(),
        ),
        (
            Source::ChromeForTesting,
            roots
                .puppeteer
                .iter()
                .flat_map(|root| puppeteer_candidates(root))
                .collect(),
        ),
        (Source::DistroChromium, roots.distro.clone()),
    ];
    for (source, candidates) in groups {
        for candidate in candidates {
            if fs::metadata(&candidate).is_err() {
                continue;
            }
            match check_binary(&candidate, trust, version_of) {
                Ok(info) if info.kind.is_supported() => return Ok((info, source)),
                Ok(info) => passed_over.push(format!(
                    "{} is {}, which is not supported",
                    candidate.display(),
                    info.kind.label()
                )),
                Err(rejection) => passed_over.push(rejection.message),
            }
        }
    }
    Err(Box::new(DetectionFailure { passed_over }))
}

/// The home directory of `uid` from the user database.
pub fn home_dir_of_uid(uid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 8192];
    // SAFETY: every pointer is valid for the call; `buf` outlives the use of `pw_dir` below.
    let ret = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if ret != 0 || result.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` is a NUL-terminated string inside `buf`.
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    let dir = PathBuf::from(std::ffi::OsString::from_vec(dir.to_bytes().to_vec()));
    dir.is_absolute().then_some(dir)
}

/// A bare command name looked up in `PATH`; an absolute or relative-with-slash path as it is.
fn resolve_command(command: &str) -> PathBuf {
    let path = Path::new(command);
    if command.contains('/') {
        return path.to_path_buf();
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(command))
        .find(|candidate| fs::metadata(candidate).is_ok_and(|m| m.is_file()))
        .unwrap_or_else(|| path.to_path_buf())
}

/// An explicitly named browser that is neither Chromium nor Chrome for Testing (Edge, Brave, a
/// wrapper script, ...) is accepted but was never probed.
fn warn_if_unprobed(info: &BrowserInfo) {
    if info.kind == BrowserKind::Unknown {
        log::warn!(
            "browser {} ({}) is not Chromium or Chrome for Testing: passless has not probed it, and \
             the interception extension may not load; the launch fails closed if it does not attach",
            info.path.display(),
            info.version
        );
    }
}

/// What a managed browser is started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserLaunch {
    /// The binary to execute (the path as configured or detected; its canonical form is
    /// `info.path`).
    pub executable: PathBuf,
    /// Arguments after the executable (the profile's `browser_command` tail, or the default
    /// `--headless=new`).
    pub extra_args: Vec<String>,
    pub info: BrowserInfo,
    pub source: Source,
}

/// Decide what the managed browser of a profile runs, and refuse what cannot be used (R14):
///
/// - `browser_command` of the profile, when set, names the executable and every argument (no
///   default flag is added: its author chose headed or headless);
/// - otherwise `agents.browser_path`, otherwise auto-detection ([`detect`]), started with
///   `--headless=new` unless `headed`.
///
/// `distinct_uid` selects the V-H7 trust rule. `home` is the browser user's home directory, where
/// Playwright's and puppeteer's caches live.
pub fn resolve_launch(
    browser_command: Option<&[String]>,
    browser_path: Option<&Path>,
    home: Option<&Path>,
    distinct_uid: bool,
    headed: bool,
    version_of: VersionRunner<'_>,
) -> Result<BrowserLaunch, Box<dyn std::error::Error + Send + Sync>> {
    let trust = if distinct_uid {
        Trust::RootOwned
    } else {
        Trust::Any
    };
    if let Some(command) = browser_command
        && let Some((executable, args)) = command.split_first()
    {
        let executable = resolve_command(executable);
        let info = check_binary(&executable, trust, version_of)?;
        warn_if_unprobed(&info);
        // The canonical path that was checked is the one that runs, not a name that could resolve
        // to something else between the check and the spawn.
        return Ok(BrowserLaunch {
            executable: info.path.clone(),
            extra_args: args.to_vec(),
            info,
            source: Source::Explicit,
        });
    }
    let (info, source) = detect(
        browser_path,
        &SearchRoots::for_home(home),
        trust,
        version_of,
    )?;
    warn_if_unprobed(&info);
    let mut extra_args = Vec::new();
    if !headed {
        extra_args.push("--headless=new".to_string());
    }
    Ok(BrowserLaunch {
        executable: info.path.clone(),
        extra_args,
        info,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn a_profile_command_wins_and_adds_no_default_flag_while_detection_defaults_to_headless() {
        let tmp = tempfile::tempdir().unwrap();
        let chromium = tmp.path().join("bin/chromium");
        script(&chromium);
        let command = vec![
            chromium.to_string_lossy().into_owned(),
            "--window-size=800,600".to_string(),
        ];
        let launch = resolve_launch(Some(&command), None, None, false, false, &versions).unwrap();
        assert_eq!(launch.extra_args, ["--window-size=800,600"]);
        assert_eq!(launch.source, Source::Explicit);
        // The canonical binary that was checked is what runs.
        assert_eq!(launch.executable, fs::canonicalize(&chromium).unwrap());
        assert_eq!(launch.executable, launch.info.path);

        // No profile command: agents.browser_path, headless by default and headed on request.
        let launch = resolve_launch(None, Some(&chromium), None, false, false, &versions).unwrap();
        assert_eq!(launch.extra_args, ["--headless=new"]);
        let launch = resolve_launch(None, Some(&chromium), None, false, true, &versions).unwrap();
        assert!(launch.extra_args.is_empty());

        // A refused browser named by the profile command is refused too.
        let branded = tmp.path().join("branded/google-chrome");
        script(&branded);
        let command = vec![branded.to_string_lossy().into_owned()];
        let err = resolve_launch(Some(&command), None, None, false, false, &versions)
            .unwrap_err()
            .to_string();
        assert!(err.contains("branded Google Chrome"), "{err}");
    }

    #[test]
    fn the_home_directory_of_the_current_user_resolves() {
        let uid = unsafe { libc::getuid() };
        if let Some(home) = home_dir_of_uid(uid) {
            assert!(home.is_absolute());
        }
        assert_eq!(home_dir_of_uid(u32::MAX - 7), None);
    }

    fn script(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "#!/bin/sh\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A `--version` runner that answers by the path's file name or the directory above it.
    fn versions(path: &Path) -> Result<String, String> {
        // Only the last three components: the tempdir's random name must not matter.
        let mut parts: Vec<String> = path
            .components()
            .rev()
            .take(3)
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        parts.reverse();
        let text = parts.join("/");
        Ok(if text.contains("branded") {
            "Google Chrome 157.0.8103.38 ".to_string()
        } else if text.contains("headless") {
            // What the real chrome-headless-shell prints (Playwright 1.64, revision 1247).
            "Google Chrome for Testing 155.0.8059.12 ".to_string()
        } else if text.contains("cft") || text.contains("chromium-1") {
            "Google Chrome for Testing 157.0.8100.10 ".to_string()
        } else if text.contains("wrapper") {
            "Brave Browser 1.90".to_string()
        } else {
            "Chromium 156.0.8078.79 Arch Linux".to_string()
        })
    }

    #[test]
    fn versions_are_classified_and_the_branded_check_does_not_match_chrome_for_testing() {
        use BrowserKind::*;
        for (text, kind) in [
            ("Chromium 156.0.8078.79 Arch Linux", Chromium),
            ("Google Chrome for Testing 155.0.8059.12 ", ChromeForTesting),
            ("Google Chrome for Testing 157.0.8100.10", ChromeForTesting),
            ("Google Chrome 157.0.8103.38 ", BrandedChrome),
            ("Google Chrome Beta 158.0.1.2", BrandedChrome),
            ("Google Chrome Dev 159.0.1.2", BrandedChrome),
            ("Brave Browser 1.90.1 Chromium: 156.0", Unknown),
            ("Microsoft Edge 156.0", Unknown),
            ("", Unknown),
        ] {
            assert_eq!(kind_from_version(text), kind, "{text:?}");
        }
    }

    #[test]
    fn headless_shell_is_recognised_by_name_or_install_path() {
        for path in [
            "/usr/bin/chrome-headless-shell",
            "/home/u/.cache/puppeteer/chrome-headless-shell/linux-155.0.1/chrome-headless-shell-linux64/chrome-headless-shell",
            "/home/u/.cache/ms-playwright/chromium_headless_shell-1247/chrome-headless-shell-linux64/chrome-headless-shell",
            "/home/u/.cache/ms-playwright/chromium_headless_shell-1247/chrome-linux/headless_shell",
            "/opt/Chrome-Headless-Shell/bin/chrome",
        ] {
            assert_eq!(
                kind_from_path(Path::new(path)),
                Some(BrowserKind::HeadlessShell),
                "{path}"
            );
        }
        for path in [
            "/usr/bin/chromium",
            "/home/u/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome",
            "/home/u/.cache/puppeteer/chrome/linux-157.0.1/chrome-linux64/chrome",
        ] {
            assert_eq!(kind_from_path(Path::new(path)), None, "{path}");
        }
    }

    #[test]
    fn branded_chrome_is_recognised_by_name_or_install_path() {
        for path in [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/opt/google/chrome/chrome",
            "/opt/google/chrome-beta/chrome",
            "/opt/google/chrome-unstable/google-chrome-unstable",
        ] {
            assert_eq!(
                kind_from_path(Path::new(path)),
                Some(BrowserKind::BrandedChrome),
                "{path}"
            );
        }
    }

    #[test]
    fn a_refused_binary_gets_an_actionable_message_and_is_never_run_blindly() {
        let tmp = tempfile::tempdir().unwrap();
        let branded = tmp.path().join("branded/google-chrome-stable");
        let headless = tmp
            .path()
            .join("x/chrome-headless-shell-linux64/chrome-headless-shell");
        script(&branded);
        script(&headless);

        let err = check_binary(&branded, Trust::Any, &versions).unwrap_err();
        assert_eq!(err.kind, BrowserKind::BrandedChrome);
        assert!(err.message.contains("branded Google Chrome"), "{err}");
        assert!(err.message.contains("--load-extension"), "{err}");
        assert!(err.message.contains("playwright install chromium"), "{err}");

        let err = check_binary(&headless, Trust::Any, &versions).unwrap_err();
        assert_eq!(err.kind, BrowserKind::HeadlessShell);
        assert!(err.message.contains("loads no extensions"), "{err}");
        assert!(
            err.message
                .contains("Google Chrome for Testing 155.0.8059.12"),
            "the real --version string is quoted: {err}"
        );
        assert!(err.message.contains("--headless=new"), "{err}");

        // A symlink with an innocent name to a headless shell is refused too.
        let link = tmp.path().join("chromium");
        symlink(&headless, &link).unwrap();
        let err = check_binary(&link, Trust::Any, &versions).unwrap_err();
        assert_eq!(err.kind, BrowserKind::HeadlessShell, "{err}");

        // The version line alone refuses a branded binary whose name gives nothing away.
        let renamed = tmp.path().join("branded/my-browser");
        script(&renamed);
        let err = check_binary(&renamed, Trust::Any, &versions).unwrap_err();
        assert_eq!(err.kind, BrowserKind::BrandedChrome);
    }

    #[test]
    fn supported_browsers_are_accepted_and_unknown_ones_pass_when_named() {
        let tmp = tempfile::tempdir().unwrap();
        let chromium = tmp.path().join("bin/chromium");
        let cft = tmp.path().join("cft/chrome");
        let wrapper = tmp.path().join("wrapper/browser");
        for p in [&chromium, &cft, &wrapper] {
            script(p);
        }
        let info = check_binary(&chromium, Trust::Any, &versions).unwrap();
        assert_eq!(info.kind, BrowserKind::Chromium);
        assert_eq!(info.path, fs::canonicalize(&chromium).unwrap());
        assert_eq!(
            check_binary(&cft, Trust::Any, &versions).unwrap().kind,
            BrowserKind::ChromeForTesting
        );
        assert_eq!(
            check_binary(&wrapper, Trust::Any, &versions).unwrap().kind,
            BrowserKind::Unknown
        );

        // Not an executable file, or missing.
        let data = tmp.path().join("data");
        fs::write(&data, "x").unwrap();
        assert!(check_binary(&data, Trust::Any, &versions).is_err());
        assert!(check_binary(&tmp.path().join("missing"), Trust::Any, &versions).is_err());
        // A binary that does not run reports why.
        let err = check_binary(&chromium, Trust::Any, &|_| Err("boom".into())).unwrap_err();
        assert!(err.message.contains("did not report a version"), "{err}");
    }

    #[test]
    fn distinct_uid_deployments_accept_only_root_owned_unwritable_binaries() {
        if unsafe { libc::geteuid() } == 0 {
            return; // every file the test makes would be root's
        }
        let tmp = tempfile::tempdir().unwrap();
        let chromium = tmp.path().join("bin/chromium");
        script(&chromium);
        // A binary the test user owns is not root's: refused for a distinct-UID principal.
        let err = check_binary(&chromium, Trust::RootOwned, &versions).unwrap_err();
        assert!(err.message.contains("distinct-UID principal"), "{err}");
        assert!(err.message.contains("owned by root"), "{err}");
        // The distribution's own binary is root's on a root-owned path (when installed).
        if Path::new("/usr/bin/chromium").exists() {
            let info = check_binary(Path::new("/usr/bin/chromium"), Trust::RootOwned, &versions);
            assert!(info.is_ok(), "{info:?}");
        }
    }

    #[test]
    fn detection_follows_the_d4_order_and_skips_what_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let pw = tmp.path().join("playwright");
        let pup = tmp.path().join("puppeteer");
        let distro = tmp.path().join("usr/bin/chromium");
        // Playwright: an older and a newer revision, and a headless shell that must never match.
        script(&pw.join("chromium-1100/chrome-linux/chrome"));
        script(&pw.join("chromium-1247/chrome-linux64/chrome"));
        script(&pw.join(
            "chromium_headless_shell-1247/chrome-headless-shell-linux64/chrome-headless-shell",
        ));
        script(&pup.join("chrome/linux-157.0.8100.10/chrome-linux64/chrome"));
        script(&pup.join("chrome/linux-99.0.1.1/chrome-linux64/chrome"));
        script(&distro);
        let roots = SearchRoots {
            playwright: vec![pw.clone()],
            puppeteer: vec![pup.clone()],
            distro: vec![distro.clone()],
        };

        let (info, source) = detect(None, &roots, Trust::Any, &versions).unwrap();
        assert_eq!(source, Source::PlaywrightChromium);
        assert!(
            info.path.ends_with("chromium-1247/chrome-linux64/chrome"),
            "{info:?}"
        );

        fs::remove_dir_all(pw.join("chromium-1247")).unwrap();
        fs::remove_dir_all(pw.join("chromium-1100")).unwrap();
        let (info, source) = detect(None, &roots, Trust::Any, &versions).unwrap();
        assert_eq!(source, Source::ChromeForTesting, "{info:?}");
        assert!(
            info.path.to_string_lossy().contains("linux-157.0.8100.10"),
            "newest first"
        );

        fs::remove_dir_all(pup.join("chrome")).unwrap();
        let (info, source) = detect(None, &roots, Trust::Any, &versions).unwrap();
        assert_eq!(source, Source::DistroChromium, "{info:?}");

        // An explicit path wins, and a refused explicit path is an error, not a fallback.
        let cft = tmp.path().join("cft/chrome");
        script(&cft);
        let (info, source) = detect(Some(&cft), &roots, Trust::Any, &versions).unwrap();
        assert_eq!(source, Source::Explicit);
        assert_eq!(info.kind, BrowserKind::ChromeForTesting);
        let branded = tmp.path().join("branded/google-chrome");
        script(&branded);
        let err = detect(Some(&branded), &roots, Trust::Any, &versions)
            .unwrap_err()
            .to_string();
        assert!(err.contains("branded Google Chrome"), "{err}");
    }

    #[test]
    fn nothing_found_lists_what_was_passed_over() {
        let tmp = tempfile::tempdir().unwrap();
        let branded = tmp.path().join("branded/google-chrome");
        script(&branded);
        let roots = SearchRoots {
            playwright: vec![tmp.path().join("none")],
            puppeteer: Vec::new(),
            distro: vec![branded, tmp.path().join("absent")],
        };
        let err = detect(None, &roots, Trust::Any, &versions)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no supported browser found"), "{err}");
        assert!(err.contains("branded Google Chrome"), "{err}");
        assert!(err.contains("playwright install chromium"), "{err}");
    }

    #[test]
    fn the_real_version_run_reads_the_first_line_and_times_out_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let ok = tmp.path().join("ok");
        fs::write(&ok, "#!/bin/sh\necho 'Chromium 1.2.3 Test'\necho second\n").unwrap();
        fs::set_permissions(&ok, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(run_version(&ok).unwrap(), "Chromium 1.2.3 Test");
        let bad = tmp.path().join("bad");
        fs::write(&bad, "#!/bin/sh\nexit 3\n").unwrap();
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(run_version(&bad).is_err());
    }
}
