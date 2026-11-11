//! The daemon side of escalation prompts (ADR 0014 section 8.2; plan P7 section 1).
//!
//! [`NotificationPrompter`] is the escalation coordinator's [`Prompter`]. One driver thread per
//! profile owns that profile's prompt child (`escalation_prompt.rs`): it spawns the child, sends
//! it the prompt, reads its events, posts the decisions into the coordinator, and withdraws the
//! child when told. The daemon itself never connects to a session bus.
//!
//! - The child must report `shown` within [`SHOWN_TIMEOUT`], or the prompt fails.
//! - A withdrawal sends `{"withdraw":true}` and closes the child's stdin; a child that has not
//!   exited within [`WITHDRAW_GRACE`] is killed with `SIGKILL`.
//! - "Allow always" earlier than the minimum review delay after `shown` is a deny, and so is a
//!   dismissal. The child applies the same rule against its own clock.
//! - `server_lost` is reported as such: the coordinator expires the escalation without cooldown.
//!
//! The child runs as `agents.notify_user` when the daemon is root ([`plan_prompt_child`]),
//! connected to `unix:path=/run/user/<uid>/bus`, which must be a socket owned by that user.
//! Otherwise it runs as the daemon's user, on the daemon's own session bus.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use passless_core::agent::ProfileId;

use super::audit_events::EscalationDenyCause;
use super::escalation::{PromptEvent, PromptSink, PromptTicket, Prompter};
use super::escalation_prompt::{
    ACTION_ALLOW_ALWAYS, ACTION_DENY, ChildEvent, ControlMessage, DEFAULT_MIN_REVIEW_DELAY_MS,
    HIDDEN_ARG, MAX_LINE_BYTES, PromptFields, PromptRequest, render_prompt,
};
use super::launcher::{
    DEFAULT_RLIMIT_AS, DEFAULT_RLIMIT_CORE, DEFAULT_RLIMIT_NOFILE, DEFAULT_RLIMIT_NPROC,
    HardenedChildSetup,
};
use super::lock_order::{self, LockLevel};

/// The child must report `shown` within this time.
pub const SHOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// A withdrawn child still running after this time is killed.
pub const WITHDRAW_GRACE: Duration = Duration::from_secs(2);
/// "Allow always" earlier than this after `shown` is a deny.
pub const MIN_REVIEW_DELAY: Duration = Duration::from_millis(DEFAULT_MIN_REVIEW_DELAY_MS);

/// Identity mode recorded by historic `prompt.*` audit records (P0–P6). Nothing emits those any
/// more; the type stays so old audit logs still deserialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptMode {
    Isolated,
}

/// Action recorded by historic `prompt.*` audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptAction {
    Register,
    Authenticate,
}

/// Error kind recorded by historic `prompt.error` audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptErrorKind {
    NotificationUnsupported,
    ServerCapabilityRejected,
    RenderFailed,
    ActionAmbiguous,
    InternalError,
}

/// Who the prompt child runs as and which bus it uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptChildPlan {
    /// The `(uid, gid)` to drop to; `None` keeps the daemon's user.
    pub target: Option<(u32, u32)>,
    /// The child's only environment variable, `DBUS_SESSION_BUS_ADDRESS`.
    pub bus_address: String,
}

/// Resolves user names (a seam for tests).
pub trait UserDirectory {
    /// `(uid, primary gid)` of `name`.
    fn lookup(&self, name: &str) -> Option<(u32, u32)>;
}

/// The system user database.
pub struct SystemUsers;

impl UserDirectory for SystemUsers {
    fn lookup(&self, name: &str) -> Option<(u32, u32)> {
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .map(|user| (user.uid.as_raw(), user.gid.as_raw()))
    }
}

/// What a bus socket path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketInfo {
    pub is_socket: bool,
    pub owner: u32,
}

/// Inspects a bus socket path without following symlinks (a seam for tests).
pub trait SocketProbe {
    fn probe(&self, path: &Path) -> io::Result<SocketInfo>;
}

/// The file system.
pub struct FsSockets;

impl SocketProbe for FsSockets {
    fn probe(&self, path: &Path) -> io::Result<SocketInfo> {
        let metadata = std::fs::symlink_metadata(path)?;
        Ok(SocketInfo {
            is_socket: metadata.file_type().is_socket(),
            owner: metadata.uid(),
        })
    }
}

/// `/run/user/<uid>/bus`.
pub fn user_bus_path(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{}/bus", uid))
}

/// The bus address of `uid`'s session bus, if its socket is a socket owned by `uid`.
fn user_bus_address(uid: u32, sockets: &dyn SocketProbe) -> Result<String, String> {
    let path = user_bus_path(uid);
    let info = sockets
        .probe(&path)
        .map_err(|e| format!("no session bus at {}: {}", path.display(), e))?;
    if !info.is_socket {
        return Err(format!("{} is not a socket", path.display()));
    }
    if info.owner != uid {
        return Err(format!(
            "{} is owned by uid {}, not {}",
            path.display(),
            info.owner,
            uid
        ));
    }
    Ok(format!("unix:path={}", path.display()))
}

/// Decide who the prompt child runs as and which bus it connects to (ADR 0014 section 8.2).
///
/// - A root daemon needs `agents.notify_user`, which must resolve to a non-root user; the child
///   drops to that user and uses `unix:path=/run/user/<uid>/bus`, which must be a socket owned by
///   that user.
/// - Any other daemon keeps its own user (a configured `notify_user` must be that user) and uses
///   its own `DBUS_SESSION_BUS_ADDRESS`, or `/run/user/<euid>/bus` under the same checks.
///
/// An `Err` makes escalation unavailable (`escalation_unavailable`).
pub fn plan_prompt_child(
    daemon_euid: u32,
    notify_user: Option<&str>,
    own_bus_address: Option<&str>,
    users: &dyn UserDirectory,
    sockets: &dyn SocketProbe,
) -> Result<PromptChildPlan, String> {
    if daemon_euid == 0 {
        let name =
            notify_user.ok_or("the daemon runs as root and agents.notify_user is not set")?;
        let (uid, gid) = users
            .lookup(name)
            .ok_or_else(|| format!("agents.notify_user '{}' does not exist", name))?;
        if uid == 0 {
            return Err("agents.notify_user must not be root".to_string());
        }
        let bus_address = user_bus_address(uid, sockets)?;
        return Ok(PromptChildPlan {
            target: Some((uid, gid)),
            bus_address,
        });
    }
    if let Some(name) = notify_user {
        let (uid, _) = users
            .lookup(name)
            .ok_or_else(|| format!("agents.notify_user '{}' does not exist", name))?;
        if uid != daemon_euid {
            return Err(format!(
                "agents.notify_user '{}' is not the daemon's user; a non-root daemon can only \
                 reach its own session bus",
                name
            ));
        }
    }
    if let Some(address) = own_bus_address.filter(|address| !address.is_empty()) {
        return Ok(PromptChildPlan {
            target: None,
            bus_address: address.to_string(),
        });
    }
    Ok(PromptChildPlan {
        target: None,
        bus_address: user_bus_address(daemon_euid, sockets)?,
    })
}

/// A running prompt child: its stdin and stdout, and the process when it is one.
pub struct PromptChild {
    stdin: Option<Box<dyn Write + Send>>,
    stdout: Option<Box<dyn Read + Send>>,
    process: Option<Child>,
}

impl PromptChild {
    /// Close stdin; kill and reap the process.
    fn kill(&mut self) {
        self.stdin = None;
        if let Some(process) = self.process.as_mut() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }

    /// Ask the child to close its notification and exit.
    fn withdraw(&mut self) {
        if let Some(stdin) = self.stdin.as_mut()
            && let Ok(mut line) = serde_json::to_vec(&ControlMessage { withdraw: true })
        {
            line.push(b'\n');
            let _ = stdin.write_all(&line).and_then(|()| stdin.flush());
        }
        self.stdin = None;
    }

    #[cfg(test)]
    fn pid(&self) -> Option<u32> {
        self.process.as_ref().map(Child::id)
    }
}

/// Starts prompt children.
pub trait PromptChildSpawner: Send + Sync {
    /// Whether a child could be started now.
    fn available(&self) -> Result<(), String>;
    fn spawn(&self) -> Result<PromptChild, String>;
}

type Planner = Box<dyn Fn() -> Result<PromptChildPlan, String> + Send + Sync>;

/// Re-executes the daemon binary as the prompt child, hardened in `pre_exec`.
pub struct ProcessSpawner {
    program: PathBuf,
    args: Vec<String>,
    planner: Planner,
    daemon_uid: u32,
    daemon_gid: u32,
}

impl ProcessSpawner {
    /// `/proc/self/exe __agent-escalation-prompt`, planned from `agents.notify_user` and the
    /// daemon's own session bus address.
    pub fn new(notify_user: Option<String>) -> Self {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let own_bus_address = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
        Self::with_planner(
            PathBuf::from("/proc/self/exe"),
            vec![HIDDEN_ARG.to_string()],
            Box::new(move || {
                plan_prompt_child(
                    euid,
                    notify_user.as_deref(),
                    own_bus_address.as_deref(),
                    &SystemUsers,
                    &FsSockets,
                )
            }),
        )
    }

    fn with_planner(program: PathBuf, args: Vec<String>, planner: Planner) -> Self {
        // SAFETY: geteuid and getegid have no preconditions and cannot fail.
        let (daemon_uid, daemon_gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Self {
            program,
            args,
            planner,
            daemon_uid,
            daemon_gid,
        }
    }
}

impl PromptChildSpawner for ProcessSpawner {
    fn available(&self) -> Result<(), String> {
        (self.planner)().map(|_| ())
    }

    fn spawn(&self) -> Result<PromptChild, String> {
        let plan = (self.planner)()?;
        let (target_uid, target_gid) = plan.target.unwrap_or((self.daemon_uid, self.daemon_gid));
        let setup = HardenedChildSetup {
            target_uid,
            target_gid,
            daemon_uid: self.daemon_uid,
            daemon_gid: self.daemon_gid,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
            bind_parent_death: true,
        };
        setup.validate().map_err(|e| e.to_string())?;
        // SAFETY: getpid has no preconditions and cannot fail.
        let parent = unsafe { libc::getpid() };
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .env_clear()
            .env("DBUS_SESSION_BUS_ADDRESS", &plan.bus_address)
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // SAFETY: `apply_prompt_child` allocates nothing and calls only async-signal-safe
        // functions; it runs in the forked child before exec.
        unsafe {
            command.pre_exec(move || setup.apply_prompt_child(parent));
        }
        let mut process = command
            .spawn()
            .map_err(|e| format!("cannot start the prompt child: {}", e))?;
        let stdin = process
            .stdin
            .take()
            .map(|s| Box::new(s) as Box<dyn Write + Send>);
        let stdout = process
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>);
        Ok(PromptChild {
            stdin,
            stdout,
            process: Some(process),
        })
    }
}

/// A message to a profile's driver thread.
enum DriverMessage {
    Show {
        ticket: PromptTicket,
        request: PromptRequest,
        sink: Weak<dyn PromptSink>,
        events: Sender<DriverMessage>,
    },
    Withdraw {
        seq: u64,
    },
    /// A line from the child of `seq`; `None` at EOF.
    Child {
        seq: u64,
        line: Option<String>,
    },
}

/// The driver's timing.
#[derive(Clone, Copy, Debug)]
struct Timing {
    shown_timeout: Duration,
    withdraw_grace: Duration,
    min_review_delay: Duration,
}

/// The [`Prompter`] that shows escalation prompts as desktop notifications through prompt
/// children.
pub struct NotificationPrompter {
    spawner: Arc<dyn PromptChildSpawner>,
    timing: Timing,
    /// Per-profile driver channels (`LockLevel::PromptDriver`, a leaf: only sends under it).
    drivers: Mutex<HashMap<ProfileId, Sender<DriverMessage>>>,
}

impl NotificationPrompter {
    pub fn new(spawner: Arc<dyn PromptChildSpawner>) -> Self {
        Self::with_timing(
            spawner,
            Timing {
                shown_timeout: SHOWN_TIMEOUT,
                withdraw_grace: WITHDRAW_GRACE,
                min_review_delay: MIN_REVIEW_DELAY,
            },
        )
    }

    fn with_timing(spawner: Arc<dyn PromptChildSpawner>, timing: Timing) -> Self {
        Self {
            spawner,
            timing,
            drivers: Mutex::new(HashMap::new()),
        }
    }

    /// Send `message` to `profile`'s driver, starting the driver on first use. A `Show` carries
    /// the driver's sender for its child's reader; the driver thread holds no sender of its own,
    /// so it exits once the prompter and every child reader are gone.
    fn send(&self, profile: &ProfileId, mut message: DriverMessage) {
        let mut drivers = lock_order::lock(&self.drivers, LockLevel::PromptDriver);
        if let Some(driver) = drivers.get(profile) {
            if let DriverMessage::Show { events, .. } = &mut message {
                *events = driver.clone();
            }
            match driver.send(message) {
                Ok(()) => return,
                Err(mpsc::SendError(returned)) => message = returned,
            }
        }
        let (sender, receiver) = mpsc::channel();
        if let DriverMessage::Show { events, .. } = &mut message {
            *events = sender.clone();
        }
        let spawner = Arc::clone(&self.spawner);
        let timing = self.timing;
        if let Err(e) = thread::Builder::new()
            .name(format!("prompt-{}", profile))
            .spawn(move || drive(receiver, spawner, timing))
        {
            warn!("prompt: cannot start the driver of '{}': {}", profile, e);
            if let DriverMessage::Show { ticket, sink, .. } = message {
                report(&sink, &ticket, PromptEvent::Failed(e.to_string()));
            }
            return;
        }
        let _ = sender.send(message);
        drivers.insert(profile.clone(), sender);
    }
}

impl Prompter for NotificationPrompter {
    fn available(&self, _profile: &ProfileId) -> Result<(), String> {
        self.spawner.available()
    }

    fn show(&self, ticket: PromptTicket, fields: PromptFields, sink: Weak<dyn PromptSink>) {
        let (summary, body) = match render_prompt(&fields) {
            Ok(text) => text,
            Err(e) => {
                report(&sink, &ticket, PromptEvent::Failed(e));
                return;
            }
        };
        let delay_ms = u64::try_from(self.timing.min_review_delay.as_millis()).unwrap_or(u64::MAX);
        let request = PromptRequest::new(summary, body, delay_ms);
        let profile = ticket.profile.clone();
        // `send` replaces `events` with the driver's sender.
        let (events, _) = mpsc::channel::<DriverMessage>();
        self.send(
            &profile,
            DriverMessage::Show {
                ticket,
                request,
                sink,
                events,
            },
        );
    }

    fn withdraw(&self, ticket: &PromptTicket) {
        self.send(&ticket.profile, DriverMessage::Withdraw { seq: ticket.seq });
    }
}

fn report(sink: &Weak<dyn PromptSink>, ticket: &PromptTicket, event: PromptEvent) {
    if let Some(sink) = sink.upgrade() {
        sink.prompt_event(ticket, event);
    }
}

/// One child the driver owns.
struct Slot {
    ticket: PromptTicket,
    child: PromptChild,
    sink: Weak<dyn PromptSink>,
    spawned: Instant,
    shown: Option<Instant>,
    /// Set once the child is retired (decided, failed or withdrawn): killed at this time if it
    /// has not exited.
    kill_at: Option<Instant>,
}

impl Slot {
    fn deadline(&self, timing: Timing) -> Option<Instant> {
        match (self.kill_at, self.shown) {
            (Some(kill_at), _) => Some(kill_at),
            (None, None) => Some(self.spawned + timing.shown_timeout),
            (None, Some(_)) => None,
        }
    }

    fn retire(&mut self, grace: Duration) {
        self.child.stdin = None;
        self.kill_at = Some(Instant::now() + grace);
    }
}

/// Read the child's stdout lines into the driver's channel.
fn forward_lines(seq: u64, stdout: Box<dyn Read + Send>, events: Sender<DriverMessage>) {
    let mut reader = BufReader::new(stdout);
    loop {
        let mut line = String::new();
        let limit = (MAX_LINE_BYTES + 1) as u64;
        match reader.by_ref().take(limit).read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) if line.len() > MAX_LINE_BYTES => break,
            Ok(_) => {
                let line = Some(line.trim_end().to_string());
                if events.send(DriverMessage::Child { seq, line }).is_err() {
                    return;
                }
            }
        }
    }
    let _ = events.send(DriverMessage::Child { seq, line: None });
}

/// A profile's driver thread. It exits when the prompter and every child reader are gone.
fn drive(receiver: Receiver<DriverMessage>, spawner: Arc<dyn PromptChildSpawner>, timing: Timing) {
    let mut slots: HashMap<u64, Slot> = HashMap::new();
    loop {
        let deadline = slots
            .values()
            .filter_map(|slot| slot.deadline(timing))
            .min();
        let message = match deadline {
            None => match receiver.recv() {
                Ok(message) => Some(message),
                Err(_) => break,
            },
            Some(at) => match receiver.recv_timeout(at.saturating_duration_since(Instant::now())) {
                Ok(message) => Some(message),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => break,
            },
        };
        if let Some(message) = message {
            handle(message, &mut slots, &spawner, timing);
        }
        expire(&mut slots, timing);
    }
    for slot in slots.values_mut() {
        slot.child.kill();
    }
}

fn handle(
    message: DriverMessage,
    slots: &mut HashMap<u64, Slot>,
    spawner: &Arc<dyn PromptChildSpawner>,
    timing: Timing,
) {
    match message {
        DriverMessage::Show {
            ticket,
            request,
            sink,
            events,
        } => {
            let seq = ticket.seq;
            let mut child = match spawner.spawn() {
                Ok(child) => child,
                Err(e) => {
                    warn!("prompt {}: {}", ticket.escalation_id, e);
                    report(&sink, &ticket, PromptEvent::Failed(e));
                    return;
                }
            };
            let sent = serde_json::to_vec(&request)
                .map_err(|e| e.to_string())
                .and_then(|mut line| {
                    line.push(b'\n');
                    let stdin = child.stdin.as_mut().ok_or("no stdin")?;
                    stdin
                        .write_all(&line)
                        .and_then(|()| stdin.flush())
                        .map_err(|e| e.to_string())
                });
            let Some(stdout) = child.stdout.take() else {
                child.kill();
                report(&sink, &ticket, PromptEvent::Failed("no stdout".to_string()));
                return;
            };
            if let Err(e) = sent {
                child.kill();
                report(
                    &sink,
                    &ticket,
                    PromptEvent::Failed(format!("cannot send the prompt: {}", e)),
                );
                return;
            }
            if let Err(e) = thread::Builder::new()
                .name(format!("prompt-read-{}", seq))
                .spawn(move || forward_lines(seq, stdout, events))
            {
                child.kill();
                report(&sink, &ticket, PromptEvent::Failed(e.to_string()));
                return;
            }
            debug!("prompt {}: child started", ticket.escalation_id);
            slots.insert(
                seq,
                Slot {
                    ticket,
                    child,
                    sink,
                    spawned: Instant::now(),
                    shown: None,
                    kill_at: None,
                },
            );
        }
        DriverMessage::Withdraw { seq } => {
            if let Some(slot) = slots.get_mut(&seq)
                && slot.kill_at.is_none()
            {
                info!("prompt {}: withdrawn", slot.ticket.escalation_id);
                slot.child.withdraw();
                slot.kill_at = Some(Instant::now() + timing.withdraw_grace);
            }
        }
        DriverMessage::Child { seq, line: None } => {
            if let Some(mut slot) = slots.remove(&seq) {
                if slot.kill_at.is_none() {
                    report(
                        &slot.sink,
                        &slot.ticket,
                        PromptEvent::Failed("the prompt child exited".to_string()),
                    );
                }
                slot.child.kill();
            }
        }
        DriverMessage::Child {
            seq,
            line: Some(line),
        } => {
            let Some(slot) = slots.get_mut(&seq) else {
                return;
            };
            if slot.kill_at.is_some() {
                return;
            }
            let event = match serde_json::from_str::<ChildEvent>(&line) {
                Ok(event) => event,
                Err(e) => {
                    warn!(
                        "prompt {}: ignoring a malformed child line: {}",
                        slot.ticket.escalation_id, e
                    );
                    return;
                }
            };
            let decided = match event {
                ChildEvent::Shown { id, server } => {
                    info!(
                        "prompt {}: shown by '{}' (notification {})",
                        slot.ticket.escalation_id, server, id
                    );
                    slot.shown = Some(Instant::now());
                    report(&slot.sink, &slot.ticket, PromptEvent::Shown);
                    return;
                }
                ChildEvent::Decision { action } => match action.as_str() {
                    ACTION_ALLOW_ALWAYS => match slot.shown {
                        Some(shown) if shown.elapsed() >= timing.min_review_delay => {
                            PromptEvent::Approved
                        }
                        _ => {
                            warn!(
                                "prompt {}: approval before the review delay; denying",
                                slot.ticket.escalation_id
                            );
                            PromptEvent::Denied(EscalationDenyCause::EarlyApproval)
                        }
                    },
                    ACTION_DENY => PromptEvent::Denied(EscalationDenyCause::User),
                    other => PromptEvent::Failed(format!("unknown decision '{}'", other)),
                },
                ChildEvent::Closed { reason } => {
                    debug!(
                        "prompt {}: notification closed (reason {})",
                        slot.ticket.escalation_id, reason
                    );
                    PromptEvent::Denied(EscalationDenyCause::Dismissed)
                }
                ChildEvent::ServerLost => PromptEvent::ServerLost,
                ChildEvent::Error { kind } => PromptEvent::Failed(kind.as_str().to_string()),
            };
            slot.retire(timing.withdraw_grace);
            report(&slot.sink, &slot.ticket, decided);
        }
    }
}

/// Fail children that never showed their prompt; kill retired children that did not exit.
fn expire(slots: &mut HashMap<u64, Slot>, timing: Timing) {
    let now = Instant::now();
    let due: Vec<u64> = slots
        .iter()
        .filter(|(_, slot)| slot.deadline(timing).is_some_and(|at| at <= now))
        .map(|(seq, _)| *seq)
        .collect();
    for seq in due {
        let Some(mut slot) = slots.remove(&seq) else {
            continue;
        };
        if slot.kill_at.is_none() {
            warn!(
                "prompt {}: not shown within {:?}",
                slot.ticket.escalation_id, timing.shown_timeout
            );
            report(
                &slot.sink,
                &slot.ticket,
                PromptEvent::Failed("the prompt was not shown in time".to_string()),
            );
        } else {
            warn!(
                "prompt {}: the child did not exit; killing it",
                slot.ticket.escalation_id
            );
        }
        slot.child.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap as Map;

    struct Users(Map<&'static str, (u32, u32)>);

    impl UserDirectory for Users {
        fn lookup(&self, name: &str) -> Option<(u32, u32)> {
            self.0.get(name).copied()
        }
    }

    struct Sockets(Map<PathBuf, SocketInfo>);

    impl SocketProbe for Sockets {
        fn probe(&self, path: &Path) -> io::Result<SocketInfo> {
            self.0
                .get(path)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn users() -> Users {
        Users(Map::from([
            ("alice", (1000, 1000)),
            ("bob", (1001, 1001)),
            ("root", (0, 0)),
        ]))
    }

    fn sockets(entries: &[(u32, bool, u32)]) -> Sockets {
        Sockets(
            entries
                .iter()
                .map(|&(uid, is_socket, owner)| {
                    (user_bus_path(uid), SocketInfo { is_socket, owner })
                })
                .collect(),
        )
    }

    #[test]
    fn root_daemon_drops_to_notify_user_on_its_bus() {
        let plan = plan_prompt_child(
            0,
            Some("alice"),
            None,
            &users(),
            &sockets(&[(1000, true, 1000)]),
        )
        .unwrap();
        assert_eq!(
            plan,
            PromptChildPlan {
                target: Some((1000, 1000)),
                bus_address: "unix:path=/run/user/1000/bus".to_string(),
            }
        );
        // The daemon's own bus address is never used by a root daemon.
        let plan = plan_prompt_child(
            0,
            Some("alice"),
            Some("unix:path=/tmp/evil"),
            &users(),
            &sockets(&[(1000, true, 1000)]),
        )
        .unwrap();
        assert_eq!(plan.bus_address, "unix:path=/run/user/1000/bus");
    }

    #[test]
    fn root_daemon_without_a_usable_notify_user_has_no_escalation() {
        let good = sockets(&[(1000, true, 1000)]);
        assert!(plan_prompt_child(0, None, None, &users(), &good).is_err());
        assert!(plan_prompt_child(0, Some("nobody-here"), None, &users(), &good).is_err());
        assert!(
            plan_prompt_child(0, Some("root"), None, &users(), &sockets(&[(0, true, 0)])).is_err()
        );
        // Missing bus, not a socket, or a socket owned by someone else.
        assert!(plan_prompt_child(0, Some("alice"), None, &users(), &sockets(&[])).is_err());
        assert!(
            plan_prompt_child(
                0,
                Some("alice"),
                None,
                &users(),
                &sockets(&[(1000, false, 1000)])
            )
            .is_err()
        );
        assert!(
            plan_prompt_child(
                0,
                Some("alice"),
                None,
                &users(),
                &sockets(&[(1000, true, 1001)])
            )
            .is_err()
        );
    }

    #[test]
    fn user_daemon_keeps_its_user_and_bus() {
        let none = sockets(&[]);
        let plan = plan_prompt_child(
            1000,
            None,
            Some("unix:path=/run/user/1000/bus"),
            &users(),
            &none,
        )
        .unwrap();
        assert_eq!(plan.target, None);
        assert_eq!(plan.bus_address, "unix:path=/run/user/1000/bus");
        assert!(
            plan_prompt_child(
                1000,
                Some("alice"),
                Some("unix:abstract=x"),
                &users(),
                &none
            )
            .is_ok()
        );
        // A different notify_user cannot be reached by a non-root daemon.
        assert!(
            plan_prompt_child(1000, Some("bob"), Some("unix:abstract=x"), &users(), &none).is_err()
        );
        // Without an address, the user's own bus socket is used if it checks out.
        let plan = plan_prompt_child(
            1000,
            None,
            Some(""),
            &users(),
            &sockets(&[(1000, true, 1000)]),
        )
        .unwrap();
        assert_eq!(plan.bus_address, "unix:path=/run/user/1000/bus");
        assert!(plan_prompt_child(1000, None, None, &users(), &none).is_err());
    }

    #[test]
    fn the_planned_identity_passes_the_hardened_setup_checks() {
        let setup = |target: (u32, u32), daemon: (u32, u32)| HardenedChildSetup {
            target_uid: target.0,
            target_gid: target.1,
            daemon_uid: daemon.0,
            daemon_gid: daemon.1,
            rlimit_nofile: DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
            bind_parent_death: true,
        };
        assert!(setup((1000, 1000), (0, 0)).validate().is_ok());
        assert!(setup((1000, 1000), (1000, 1000)).validate().is_ok());
        assert!(setup((0, 0), (0, 0)).validate().is_err());
        assert!(setup((1001, 1001), (1000, 1000)).validate().is_err());
    }

    /// Runs `script` under `/bin/sh` with the prompt child's hardening and returns its output.
    fn run_hardened(script: &str) -> String {
        let spawner = ProcessSpawner::with_planner(
            PathBuf::from("/bin/sh"),
            vec!["-c".to_string(), script.to_string()],
            Box::new(|| {
                Ok(PromptChildPlan {
                    target: None,
                    bus_address: "unix:path=/nonexistent/bus".to_string(),
                })
            }),
        );
        let mut child = spawner.spawn().unwrap();
        child.stdin = None;
        let mut output = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        child.kill();
        output
    }

    #[test]
    fn process_child_has_a_scrubbed_environment_no_new_privs_and_no_inherited_fds() {
        // An inheritable descriptor in the daemon must not reach the child. It is placed at 100
        // or above so it never takes a free stdio slot of the test process.
        // SAFETY: plain open(2)/fcntl(2)/close(2) of /dev/null; the copy is closed below.
        let leaked = unsafe {
            let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            assert!(fd >= 0);
            let high = libc::fcntl(fd, libc::F_DUPFD, 100);
            libc::close(fd);
            high
        };
        assert!(leaked >= 100);
        let output = run_hardened(
            "tr '\\0' '\\n' < /proc/$$/environ; echo ---; ls /proc/$$/fd; echo ---; \
             grep NoNewPrivs /proc/$$/status; pwd",
        );
        // SAFETY: closing the descriptor opened above.
        unsafe { libc::close(leaked) };
        let parts: Vec<&str> = output.split("---\n").collect();
        assert_eq!(parts.len(), 3, "{output}");
        let env: Vec<&str> = parts[0].lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(env, ["DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/bus"]);
        let fds: Vec<i32> = parts[1]
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        assert!(!fds.contains(&leaked), "fd {leaked} leaked: {fds:?}");
        assert!(fds.iter().all(|fd| *fd <= 2), "{fds:?}");
        assert!(parts[2].contains("NoNewPrivs:\t1"), "{}", parts[2]);
        assert_eq!(
            parts[2].lines().last(),
            Some("/"),
            "the working directory is /"
        );
    }
}

#[cfg(test)]
mod dbus_tests {
    //! The prompt child and the driver against `tools/notify-double` on a private, minimal
    //! `dbus-daemon` (never the real session bus).

    use super::*;

    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::Mutex as StdMutex;

    use futures_lite::StreamExt;
    use notify_double::server::{Config, NotificationDouble};
    use notify_double::{LogWriter, OBJECT_PATH, Script, WELL_KNOWN_NAME};
    use serde_json::Value as Json;

    use crate::agent::escalation::EscalationId;
    use crate::agent::escalation_prompt::{ChildErrorKind, InProcessChild, PromptVerb};

    const EVENT_WAIT: Duration = Duration::from_secs(10);

    /// A private session bus with no service activation, killed and reaped on drop.
    struct PrivateBus {
        // Field order matters: the daemon is killed before its directory is removed.
        daemon: Child,
        dir: tempfile::TempDir,
        address: String,
    }

    impl PrivateBus {
        fn start() -> Self {
            // Keep the socket path short (sun_path is limited to ~108 bytes).
            let base = if std::env::temp_dir().as_os_str().len() > 40 {
                PathBuf::from("/tmp")
            } else {
                std::env::temp_dir()
            };
            let dir = tempfile::Builder::new()
                .prefix("passless-bus-")
                .tempdir_in(base)
                .expect("scratch dir");
            let sock = dir.path().join("bus.sock");
            let conf = dir.path().join("bus.conf");
            fs::write(
                &conf,
                format!(
                    "<busconfig>\n<type>session</type>\n<listen>unix:path={}</listen>\n\
                     <auth>EXTERNAL</auth>\n<policy context=\"default\">\n\
                     <allow send_destination=\"*\" eavesdrop=\"true\"/>\n\
                     <allow eavesdrop=\"true\"/>\n<allow own=\"*\"/>\n<allow user=\"*\"/>\n\
                     </policy>\n</busconfig>\n",
                    sock.display()
                ),
            )
            .expect("bus config");
            let mut command = Command::new("dbus-daemon");
            command
                .arg(format!("--config-file={}", conf.display()))
                .args(["--nofork", "--print-address=1"])
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("HOME", dir.path())
                .env("XDG_DATA_HOME", dir.path().join("data"))
                .env("XDG_DATA_DIRS", dir.path().join("share"))
                .env("XDG_RUNTIME_DIR", dir.path())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .process_group(0);
            // SAFETY: the closure only calls the async-signal-safe `prctl`.
            unsafe {
                command.pre_exec(|| {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut daemon = command.spawn().expect("dbus-daemon");
            let stdout = daemon.stdout.take().expect("piped stdout");
            let mut address = String::new();
            let read = BufReader::new(stdout).read_line(&mut address);
            let bus = Self {
                daemon,
                dir,
                address: address.trim().to_string(),
            };
            read.expect("dbus-daemon address");
            assert!(!bus.address.is_empty());
            bus
        }
    }

    impl Drop for PrivateBus {
        fn drop(&mut self) {
            // SAFETY: the process group id equals the leader's pid (`process_group(0)`).
            unsafe {
                libc::kill(-(self.daemon.id() as i32), libc::SIGKILL);
            }
            let _ = self.daemon.kill();
            let _ = self.daemon.wait();
        }
    }

    /// `notify-double` served in-process on the private bus.
    struct Double {
        runtime: tokio::runtime::Runtime,
        conn: Option<zbus::Connection>,
        log: PathBuf,
    }

    impl Double {
        fn start(bus: &PrivateBus, script: &str, capabilities: &[&str]) -> Self {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            static DOUBLES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = DOUBLES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let log = bus.dir.path().join(format!("notify-{n}.jsonl"));
            let writer = Arc::new(LogWriter::open(&log).unwrap());
            let config = Config {
                script: Script::parse_list(script).unwrap(),
                capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
                server_name: "notify-double".to_string(),
            };
            let conn = runtime.block_on(async {
                zbus::connection::Builder::address(bus.address.as_str())
                    .name(WELL_KNOWN_NAME)
                    .serve_at(OBJECT_PATH, NotificationDouble::new(config, writer))
                    .build()
                    .await
                    .unwrap()
            });
            Self {
                runtime,
                conn: Some(conn),
                log,
            }
        }

        fn events(&self) -> Vec<Json> {
            fs::read_to_string(&self.log)
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }

        fn kinds(&self) -> Vec<String> {
            self.events()
                .iter()
                .map(|event| event["event"].as_str().unwrap().to_string())
                .collect()
        }

        fn wait_for(&self, kind: &str) -> Json {
            let start = Instant::now();
            loop {
                if let Some(event) = self.events().into_iter().find(|e| e["event"] == kind) {
                    return event;
                }
                assert!(
                    start.elapsed() < EVENT_WAIT,
                    "no {kind}: {:?}",
                    self.kinds()
                );
                thread::sleep(Duration::from_millis(20));
            }
        }

        /// Stop serving: the well-known name is released (`NameOwnerChanged`).
        fn stop(&mut self) {
            if let Some(conn) = self.conn.take() {
                self.runtime.block_on(async {
                    let _ = conn.close().await;
                });
            }
        }

        /// Emit a signal from another connection on the bus (a spoofing peer).
        fn spoof<B>(&self, bus: &PrivateBus, member: &str, body: B)
        where
            B: serde::Serialize + zbus::zvariant::DynamicType,
        {
            self.runtime.block_on(async {
                let conn = zbus::connection::Builder::address(bus.address.as_str())
                    .build()
                    .await
                    .unwrap();
                conn.emit_signal(
                    None::<zbus::names::BusName<'_>>,
                    OBJECT_PATH,
                    WELL_KNOWN_NAME,
                    member,
                    &body,
                )
                .await
                .unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
            });
        }
    }

    /// A prompt child on a thread of this process, talking the line protocol.
    struct ChildHarness {
        stdin: Option<io::PipeWriter>,
        events: Receiver<ChildEvent>,
        thread: Option<thread::JoinHandle<i32>>,
    }

    impl ChildHarness {
        fn start(bus: &PrivateBus, min_review_delay_ms: u64) -> Self {
            let mut child = InProcessChild::spawn(Some(bus.address.clone())).unwrap();
            let mut stdin = child.stdin.take().unwrap();
            let request = PromptRequest::new(
                "Passless: agent sign-in request".to_string(),
                "body".to_string(),
                min_review_delay_ms,
            );
            let mut line = serde_json::to_vec(&request).unwrap();
            line.push(b'\n');
            stdin.write_all(&line).unwrap();
            let (sender, events) = mpsc::channel();
            let stdout = child.stdout.take().unwrap();
            thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    let event: ChildEvent = serde_json::from_str(&line).unwrap();
                    if sender.send(event).is_err() {
                        break;
                    }
                }
            });
            Self {
                stdin: Some(stdin),
                events,
                thread: child.thread.take(),
            }
        }

        fn next(&self) -> ChildEvent {
            self.events
                .recv_timeout(EVENT_WAIT)
                .expect("no event from the prompt child")
        }

        fn shown(&self) -> u32 {
            match self.next() {
                ChildEvent::Shown { id, server } => {
                    assert_eq!(server, "notify-double");
                    id
                }
                other => panic!("expected shown, got {other:?}"),
            }
        }

        fn send(&mut self, line: &str) {
            let stdin = self.stdin.as_mut().unwrap();
            stdin.write_all(line.as_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
        }

        fn exit_code(&mut self) -> i32 {
            self.thread.take().unwrap().join().unwrap()
        }
    }

    #[test]
    fn child_subscribes_before_notify() {
        let bus = PrivateBus::start();
        let double = Double::start(&bus, "ignore", &["actions", "body"]);
        // An eavesdropper records every method call on the bus, in bus order.
        let calls: Arc<StdMutex<Vec<(String, String, String)>>> = Arc::default();
        let recorder = Arc::clone(&calls);
        let address = bus.address.clone();
        let eavesdropper = double.runtime.spawn(async move {
            let conn = zbus::connection::Builder::address(address.as_str())
                .build()
                .await
                .unwrap();
            let mut stream = zbus::MessageStream::from(&conn);
            conn.call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "AddMatch",
                &"type='method_call',eavesdrop='true'",
            )
            .await
            .unwrap();
            while let Some(Ok(message)) = stream.next().await {
                let header = message.header();
                if header.message_type() != zbus::message::Type::MethodCall {
                    continue;
                }
                let member = header.member().map(|m| m.to_string()).unwrap_or_default();
                let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();
                let arg = message.body().deserialize::<String>().unwrap_or_default();
                recorder.lock().unwrap().push((sender, member, arg));
            }
        });
        thread::sleep(Duration::from_millis(200));

        let mut child = ChildHarness::start(&bus, 1000);
        child.shown();
        thread::sleep(Duration::from_millis(100));
        eavesdropper.abort();

        let calls = calls.lock().unwrap().clone();
        let notify = calls
            .iter()
            .position(|(_, member, _)| member == "Notify")
            .expect("Notify recorded");
        let sender = &calls[notify].0;
        let before: Vec<&(String, String, String)> = calls[..notify]
            .iter()
            .filter(|(s, member, _)| s == sender && member == "AddMatch")
            .collect();
        assert!(
            before.iter().any(
                |(_, _, rule)| rule.contains("org.freedesktop.Notifications")
                    && rule.contains("sender='")
                    && !rule.contains("NameOwnerChanged")
            ),
            "no sender-filtered notification match before Notify: {calls:?}"
        );
        assert!(
            before
                .iter()
                .any(|(_, _, rule)| rule.contains("NameOwnerChanged")),
            "no NameOwnerChanged match before Notify: {calls:?}"
        );
        drop(child.stdin.take());
        assert_eq!(child.exit_code(), 0);
    }

    #[test]
    fn child_ignores_a_spoofed_sender() {
        let bus = PrivateBus::start();
        let double = Double::start(&bus, "deny:1500", &["actions", "body"]);
        let mut child = ChildHarness::start(&bus, 0);
        let id = child.shown();
        double.spoof(&bus, "ActionInvoked", (id, ACTION_ALLOW_ALWAYS));
        double.spoof(&bus, "NotificationClosed", (id, 2u32));
        // The first event is the real server's deny, not the spoofed approval or close.
        assert_eq!(
            child.next(),
            ChildEvent::Decision {
                action: ACTION_DENY.to_string()
            }
        );
        assert_eq!(child.exit_code(), 0);
    }

    #[test]
    fn child_reports_server_lost() {
        let bus = PrivateBus::start();
        let mut double = Double::start(&bus, "ignore", &["actions", "body"]);
        let mut child = ChildHarness::start(&bus, 1000);
        child.shown();
        double.stop();
        assert_eq!(child.next(), ChildEvent::ServerLost);
        assert_eq!(child.exit_code(), 0);
    }

    #[test]
    fn withdraw_and_eof_send_close_notification() {
        let bus = PrivateBus::start();
        let double = Double::start(&bus, "ignore", &["actions", "body"]);
        let mut child = ChildHarness::start(&bus, 1000);
        let id = child.shown();
        child.send(r#"{"withdraw":true}"#);
        assert_eq!(child.exit_code(), 0);
        let closed = double.wait_for("CloseNotification");
        assert_eq!(closed["id"], id);

        let mut child = ChildHarness::start(&bus, 1000);
        let id = child.shown();
        drop(child.stdin.take());
        assert_eq!(child.exit_code(), 0);
        let closes: Vec<Json> = double
            .events()
            .into_iter()
            .filter(|e| e["event"] == "CloseNotification")
            .collect();
        assert_eq!(closes.last().unwrap()["id"], id);
    }

    #[test]
    fn capability_gate_rejects_servers_without_actions() {
        let bus = PrivateBus::start();
        let double = Double::start(&bus, "ignore", &["body"]);
        let mut child = ChildHarness::start(&bus, 1000);
        assert_eq!(
            child.next(),
            ChildEvent::Error {
                kind: ChildErrorKind::CapabilityRejected
            }
        );
        assert_eq!(child.exit_code(), 1);
        assert!(!double.kinds().contains(&"Notify".to_string()));
    }

    #[test]
    fn child_without_a_server_or_a_bus_fails() {
        let bus = PrivateBus::start();
        let mut child = ChildHarness::start(&bus, 1000);
        assert_eq!(
            child.next(),
            ChildEvent::Error {
                kind: ChildErrorKind::NoServer
            }
        );
        assert_eq!(child.exit_code(), 1);

        let mut child = InProcessChild::spawn(None).unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(
            serde_json::from_str::<ChildEvent>(&line).unwrap(),
            ChildEvent::Error {
                kind: ChildErrorKind::BusUnavailable
            }
        );
    }

    #[test]
    fn child_denies_an_approval_before_its_review_delay() {
        let bus = PrivateBus::start();
        let _double = Double::start(&bus, "approve:0", &["actions", "body"]);
        let mut child = ChildHarness::start(&bus, 1000);
        child.shown();
        assert_eq!(
            child.next(),
            ChildEvent::Decision {
                action: ACTION_DENY.to_string()
            }
        );
        assert_eq!(child.exit_code(), 0);

        let bus = PrivateBus::start();
        let _double = Double::start(&bus, "approve:300", &["actions", "body"]);
        let mut child = ChildHarness::start(&bus, 100);
        child.shown();
        assert_eq!(
            child.next(),
            ChildEvent::Decision {
                action: ACTION_ALLOW_ALWAYS.to_string()
            }
        );
        assert_eq!(child.exit_code(), 0);
    }

    /// Records the driver's reports.
    #[derive(Default)]
    struct RecordingSink {
        events: StdMutex<Vec<PromptEvent>>,
    }

    impl PromptSink for RecordingSink {
        fn prompt_event(&self, _ticket: &PromptTicket, event: PromptEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    impl RecordingSink {
        fn wait_for(&self, count: usize) -> Vec<PromptEvent> {
            let start = Instant::now();
            loop {
                let events = self.events.lock().unwrap().clone();
                if events.len() >= count {
                    return events;
                }
                assert!(start.elapsed() < EVENT_WAIT, "only {events:?}");
                thread::sleep(Duration::from_millis(20));
            }
        }
    }

    /// Spawns the child protocol in-process (the daemon re-executes itself instead).
    struct InProcessSpawner {
        address: String,
    }

    impl PromptChildSpawner for InProcessSpawner {
        fn available(&self) -> Result<(), String> {
            Ok(())
        }

        fn spawn(&self) -> Result<PromptChild, String> {
            let mut child =
                InProcessChild::spawn(Some(self.address.clone())).map_err(|e| e.to_string())?;
            Ok(PromptChild {
                stdin: child
                    .stdin
                    .take()
                    .map(|s| Box::new(s) as Box<dyn Write + Send>),
                stdout: child
                    .stdout
                    .take()
                    .map(|s| Box::new(s) as Box<dyn Read + Send>),
                process: None,
            })
        }
    }

    fn fields() -> PromptFields {
        PromptFields {
            profile: "work".to_string(),
            mode: "isolated".to_string(),
            principal_user: "agent".to_string(),
            verb: PromptVerb::Authenticate,
            rp_id: "bücher.example".to_string(),
            origin: "https://bücher.example".to_string(),
        }
    }

    fn ticket(seq: u64) -> PromptTicket {
        PromptTicket {
            profile: ProfileId::new("work").unwrap(),
            escalation_id: EscalationId::for_tests(&format!("esc-{seq}")),
            seq,
        }
    }

    fn prompter(bus: &PrivateBus, min_review_delay: Duration) -> NotificationPrompter {
        NotificationPrompter::with_timing(
            Arc::new(InProcessSpawner {
                address: bus.address.clone(),
            }),
            Timing {
                shown_timeout: SHOWN_TIMEOUT,
                withdraw_grace: Duration::from_millis(300),
                min_review_delay,
            },
        )
    }

    fn show(prompter: &NotificationPrompter, seq: u64) -> Arc<RecordingSink> {
        let sink = Arc::new(RecordingSink::default());
        let weak: Weak<dyn PromptSink> = Arc::downgrade(&sink) as Weak<dyn PromptSink>;
        prompter.show(ticket(seq), fields(), weak);
        sink
    }

    #[test]
    fn driver_shows_daemon_fields_only_with_the_fixed_actions() {
        let bus = PrivateBus::start();
        let double = Double::start(&bus, "ignore", &["actions", "body", "body-markup"]);
        let prompter = prompter(&bus, MIN_REVIEW_DELAY);
        let sink = show(&prompter, 1);
        assert_eq!(sink.wait_for(1), [PromptEvent::Shown]);
        let notify = double.wait_for("Notify");
        let (summary, body) = render_prompt(&fields()).unwrap();
        assert_eq!(notify["summary"], summary.as_str());
        assert_eq!(notify["body"], body.as_str());
        assert!(body.contains("Profile: work (isolated)"));
        assert!(body.contains("Principal user: agent"));
        assert!(body.contains("Site: xn--bcher-kva.example (any page under this site)"));
        assert!(body.contains("Origin: https://xn--bcher-kva.example"));
        assert!(body.contains("saved permanently"));
        assert_eq!(
            notify["actions"],
            serde_json::json!(["allow_always", "Allow always", "deny", "Deny"])
        );
        assert_eq!(notify["expire_timeout"], 0);
        assert_eq!(notify["hints"]["urgency"], 2);
        assert_eq!(notify["app_name"], "Passless");

        prompter.withdraw(&ticket(1));
        let closed = double.wait_for("CloseNotification");
        assert_eq!(closed["id"], notify["id"]);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            sink.wait_for(1),
            [PromptEvent::Shown],
            "a withdrawal reports nothing"
        );
    }

    #[test]
    fn driver_maps_decisions_and_the_review_delay() {
        let bus = PrivateBus::start();
        // Approve too early, approve after the delay, deny, dismiss.
        let _double = Double::start(
            &bus,
            "invoke=allow_always:100,approve:700,deny:50,close:50",
            &["actions", "body"],
        );
        let prompter = prompter(&bus, Duration::from_millis(500));
        let expected = [
            PromptEvent::Denied(EscalationDenyCause::EarlyApproval),
            PromptEvent::Approved,
            PromptEvent::Denied(EscalationDenyCause::User),
            PromptEvent::Denied(EscalationDenyCause::Dismissed),
        ];
        for (n, want) in expected.into_iter().enumerate() {
            let sink = show(&prompter, n as u64 + 1);
            let events = sink.wait_for(2);
            assert_eq!(events[0], PromptEvent::Shown);
            // The child's own (earlier-starting) clock may already have turned the early
            // approval into a deny.
            if want == PromptEvent::Denied(EscalationDenyCause::EarlyApproval) {
                assert!(matches!(events[1], PromptEvent::Denied(_)), "{events:?}");
            } else {
                assert_eq!(events[1], want);
            }
        }
    }

    #[test]
    fn driver_reports_server_lost_and_failures() {
        let bus = PrivateBus::start();
        let mut double = Double::start(&bus, "ignore", &["actions", "body"]);
        let prompter = prompter(&bus, MIN_REVIEW_DELAY);
        let sink = show(&prompter, 1);
        sink.wait_for(1);
        double.stop();
        assert_eq!(sink.wait_for(2)[1], PromptEvent::ServerLost);

        // No server any more: the child fails before showing anything.
        let sink = show(&prompter, 2);
        assert_eq!(
            sink.wait_for(1),
            [PromptEvent::Failed("no_server".to_string())]
        );
    }

    /// A child that never answers.
    struct SilentSpawner {
        pids: StdMutex<Vec<u32>>,
    }

    impl PromptChildSpawner for SilentSpawner {
        fn available(&self) -> Result<(), String> {
            Ok(())
        }

        fn spawn(&self) -> Result<PromptChild, String> {
            let script = "trap '' TERM; while :; do sleep 1; done";
            let spawner = ProcessSpawner::with_planner(
                PathBuf::from("/bin/sh"),
                vec!["-c".to_string(), script.to_string()],
                Box::new(|| {
                    Ok(PromptChildPlan {
                        target: None,
                        bus_address: "unix:path=/nonexistent".to_string(),
                    })
                }),
            );
            let child = spawner.spawn()?;
            if let Some(pid) = child.pid() {
                self.pids.lock().unwrap().push(pid);
            }
            Ok(child)
        }
    }

    fn running(pid: u32) -> bool {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .map(|stat| !stat.contains(") Z "))
            .unwrap_or(false)
    }

    #[test]
    fn driver_fails_a_silent_child_and_kills_a_withdrawn_one() {
        let spawner = Arc::new(SilentSpawner {
            pids: StdMutex::default(),
        });
        let prompter = NotificationPrompter::with_timing(
            spawner.clone(),
            Timing {
                shown_timeout: Duration::from_millis(300),
                withdraw_grace: Duration::from_millis(300),
                min_review_delay: MIN_REVIEW_DELAY,
            },
        );
        let sink = show(&prompter, 1);
        assert_eq!(
            sink.wait_for(1),
            [PromptEvent::Failed(
                "the prompt was not shown in time".to_string()
            )]
        );
        let first = spawner.pids.lock().unwrap()[0];
        let start = Instant::now();
        while running(first) {
            assert!(start.elapsed() < EVENT_WAIT, "child {first} still running");
            thread::sleep(Duration::from_millis(20));
        }

        // A withdrawn child that ignores the withdrawal is killed after the grace period.
        let prompter = NotificationPrompter::with_timing(
            spawner.clone(),
            Timing {
                shown_timeout: Duration::from_secs(60),
                withdraw_grace: Duration::from_millis(300),
                min_review_delay: MIN_REVIEW_DELAY,
            },
        );
        let sink = show(&prompter, 2);
        let start = Instant::now();
        while spawner.pids.lock().unwrap().len() < 2 {
            assert!(start.elapsed() < EVENT_WAIT);
            thread::sleep(Duration::from_millis(20));
        }
        let second = spawner.pids.lock().unwrap()[1];
        thread::sleep(Duration::from_millis(100));
        prompter.withdraw(&ticket(2));
        thread::sleep(Duration::from_millis(100));
        assert!(running(second), "killed before the grace period");
        let start = Instant::now();
        while running(second) {
            assert!(start.elapsed() < EVENT_WAIT, "child {second} not killed");
            thread::sleep(Duration::from_millis(20));
        }
        assert!(sink.events.lock().unwrap().is_empty());
    }
}
