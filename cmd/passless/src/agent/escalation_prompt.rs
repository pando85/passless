//! The escalation prompt child (ADR 0014 section 8.2; plan P7 section 1).
//!
//! The daemon never talks to a notification server itself. For every escalation prompt it
//! re-executes its own binary (`/proc/self/exe __agent-escalation-prompt`, dispatched in `main()`
//! before any argument parsing or config load). The parent (`prompt.rs`) has already closed the
//! inherited descriptors, dropped privileges to `agents.notify_user` when it runs as root, set
//! `PR_SET_PDEATHSIG(SIGKILL)` and `PR_SET_NO_NEW_PRIVS`, and cleared the environment except
//! `DBUS_SESSION_BUS_ADDRESS`. The child owns the bus connection for exactly one prompt:
//!
//! 1. connect to the bus;
//! 2. resolve the unique name of `org.freedesktop.Notifications` (`GetNameOwner`);
//! 3. capability gate: the server must advertise `actions` and must not be a known
//!    single-action server;
//! 4. subscribe to `ActionInvoked`/`NotificationClosed` filtered on that unique sender, and to
//!    `NameOwnerChanged` for the well-known name, all before `Notify`;
//! 5. `Notify` with `expire_timeout = 0`, critical urgency and exactly the actions
//!    `allow_always` ("Allow always") and `deny` ("Deny");
//! 6. report `shown`, then exactly one of `decision`, `closed` or `server_lost` and exit. A
//!    `{"withdraw":true}` line or EOF on stdin closes the notification (`CloseNotification`) and
//!    exits. The child has no prompt timeout of its own: the daemon withdraws it.
//!
//! Protocol (JSON lines). Daemon to child: first
//! `{"v":1,"summary":…,"body":…,"actions":[["allow_always","Allow always"],["deny","Deny"]],"min_review_delay_ms":…}`,
//! later `{"withdraw":true}` or EOF. Child to daemon: `{"event":"shown","id":…,"server":…}`,
//! `{"event":"decision","action":…}`, `{"event":"closed","reason":…}`, `{"event":"server_lost"}`,
//! `{"event":"error","kind":…}`.
//!
//! An "Allow always" that arrives before `min_review_delay_ms` has passed since `Notify` returned
//! is reported as a `deny` decision. The daemon applies the same rule against its own clock.
//!
//! This file is also compiled into `agent-prompt-probe` through `#[path]`, so it depends only on
//! `std` and external crates.

use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use futures_lite::StreamExt;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use zbus::message::Type as MessageType;
use zbus::{Connection, MatchRule, Message, MessageStream};

/// The hidden first argument that turns the daemon binary into a prompt child.
pub const HIDDEN_ARG: &str = "__agent-escalation-prompt";
pub const PROTOCOL_VERSION: u32 = 1;
pub const ACTION_ALLOW_ALWAYS: &str = "allow_always";
pub const ACTION_DENY: &str = "deny";
pub const LABEL_ALLOW_ALWAYS: &str = "Allow always";
pub const LABEL_DENY: &str = "Deny";
/// The minimum review delay: an earlier "Allow always" is a deny (a heuristic, not
/// authentication; ADR 0014 section 8.2).
pub const DEFAULT_MIN_REVIEW_DELAY_MS: u64 = 1000;
/// Longest protocol line accepted on either side.
pub const MAX_LINE_BYTES: usize = 16 * 1024;

const NOTIFICATIONS_NAME: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
const NOTIFICATIONS_IFACE: &str = "org.freedesktop.Notifications";
const DBUS_NAME: &str = "org.freedesktop.DBus";
const DBUS_PATH: &str = "/org/freedesktop/DBus";
const APP_NAME: &str = "Passless";
const APP_ICON: &str = "security-high";
const URGENCY_CRITICAL: u8 = 2;
const MAX_QUEUED_SIGNALS: usize = 64;

/// The prompt the daemon asks the child to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptRequest {
    pub v: u32,
    pub summary: String,
    pub body: String,
    pub actions: Vec<(String, String)>,
    pub min_review_delay_ms: u64,
}

impl PromptRequest {
    /// A request with the only allowed action set.
    pub fn new(summary: String, body: String, min_review_delay_ms: u64) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            summary,
            body,
            actions: allowed_actions(),
            min_review_delay_ms,
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.v != PROTOCOL_VERSION {
            return Err("unsupported protocol version");
        }
        if self.actions != allowed_actions() {
            return Err("the actions must be exactly allow_always and deny");
        }
        if self.summary.is_empty() {
            return Err("empty summary");
        }
        Ok(())
    }
}

fn allowed_actions() -> Vec<(String, String)> {
    vec![
        (
            ACTION_ALLOW_ALWAYS.to_string(),
            LABEL_ALLOW_ALWAYS.to_string(),
        ),
        (ACTION_DENY.to_string(), LABEL_DENY.to_string()),
    ]
}

/// A later daemon-to-child line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlMessage {
    pub withdraw: bool,
}

/// What went wrong in the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildErrorKind {
    /// No bus address, or the connection failed.
    BusUnavailable,
    /// Nobody owns `org.freedesktop.Notifications`.
    NoServer,
    /// The server failed the capability gate.
    CapabilityRejected,
    /// `Notify` failed.
    NotifyFailed,
    /// The daemon's request was malformed.
    BadRequest,
    /// Anything else.
    Internal,
}

impl ChildErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BusUnavailable => "bus_unavailable",
            Self::NoServer => "no_server",
            Self::CapabilityRejected => "capability_rejected",
            Self::NotifyFailed => "notify_failed",
            Self::BadRequest => "bad_request",
            Self::Internal => "internal",
        }
    }
}

/// A child-to-daemon line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ChildEvent {
    Shown { id: u32, server: String },
    Decision { action: String },
    Closed { reason: u32 },
    ServerLost,
    Error { kind: ChildErrorKind },
}

/// Whether a notification server must be rejected because it is known to collapse distinct
/// actions into one default action (the capability heuristic kept from the P0 prompt).
pub fn server_rejected(name: &str, version: &str) -> bool {
    matches!(
        (name.to_lowercase().as_str(), version),
        ("notify-osd", "1.0") | ("mako", "0.0.0") | ("quickshell", "")
    )
}

/// The verb of the prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptVerb {
    Authenticate,
    Register,
}

/// The daemon-derived fields a prompt shows (ADR 0014 section 8.1 step 4). Nothing here comes
/// from the page or the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptFields {
    pub profile: String,
    pub mode: String,
    pub principal_user: String,
    pub verb: PromptVerb,
    /// The normalized RP ID; rendered in its ASCII (punycode) form.
    pub rp_id: String,
    /// The validated origin; rendered in its ASCII serialization.
    pub origin: String,
}

fn is_bidi_or_zero_width_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// One bounded visual line: no line breaks, no control, Bidi or zero-width characters, and no
/// markup characters (servers with `body-markup` would interpret them).
fn sanitize_line(input: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_bytes));
    let mut previous_was_space = false;
    for original in input.chars() {
        let ch = if matches!(original, '\n' | '\r' | '\t') {
            ' '
        } else if original.is_control()
            || is_bidi_or_zero_width_control(original)
            || matches!(original, '<' | '>' | '&')
        {
            continue;
        } else {
            original
        };
        let is_space = ch.is_whitespace();
        if is_space && previous_was_space {
            continue;
        }
        let rendered = if is_space { ' ' } else { ch };
        if out.len() + rendered.len_utf8() > max_bytes {
            break;
        }
        out.push(rendered);
        previous_was_space = is_space;
    }
    out.trim().to_string()
}

/// The RP ID in ASCII (punycode) form.
pub fn ascii_rp_id(rp_id: &str) -> Result<String, String> {
    match url::Host::parse(rp_id.trim()) {
        Ok(url::Host::Domain(domain)) if !domain.is_empty() => Ok(domain),
        Ok(other) => Ok(other.to_string()),
        Err(e) => Err(format!("RP ID '{}' cannot be rendered: {}", rp_id, e)),
    }
}

/// The origin in its ASCII serialization.
pub fn ascii_origin(origin: &str) -> Result<String, String> {
    let url = url::Url::parse(origin.trim())
        .map_err(|e| format!("origin '{}' cannot be rendered: {}", origin, e))?;
    let origin = url.origin();
    if !origin.is_tuple() {
        return Err("an opaque origin cannot be rendered".to_string());
    }
    Ok(origin.ascii_serialization())
}

/// The notification summary and body built from daemon-derived fields only.
pub fn render_prompt(fields: &PromptFields) -> Result<(String, String), String> {
    let rp_id = ascii_rp_id(&fields.rp_id)?;
    let origin = ascii_origin(&fields.origin)?;
    let (summary, action) = match fields.verb {
        PromptVerb::Authenticate => ("Passless: agent sign-in request", "sign in with a passkey"),
        PromptVerb::Register => (
            "Passless: agent registration request",
            "register a new passkey",
        ),
    };
    let body = format!(
        "Profile: {} ({})\nPrincipal user: {}\nAction: {}\nSite: {} (any page under this site)\nOrigin: {}\n\"Allow always\" is saved permanently.",
        sanitize_line(&fields.profile, 128),
        sanitize_line(&fields.mode, 32),
        sanitize_line(&fields.principal_user, 64),
        action,
        sanitize_line(&rp_id, 253),
        sanitize_line(&origin, 300),
    );
    Ok((summary.to_string(), body))
}

/// What arrives on stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Input {
    Line(String),
    Eof,
}

#[derive(Default)]
struct InboxState {
    queue: VecDeque<Input>,
    eof: bool,
    waker: Option<Waker>,
}

/// Lines read from stdin by a helper thread, awaited by the child's single async task.
#[derive(Default)]
struct Inbox {
    state: Mutex<InboxState>,
}

impl Inbox {
    fn spawn_reader<R: BufRead + Send + 'static>(mut input: R) -> io::Result<Arc<Self>> {
        let inbox = Arc::new(Self::default());
        let writer = Arc::clone(&inbox);
        thread::Builder::new()
            .name("prompt-stdin".to_string())
            .spawn(move || {
                loop {
                    let mut line = String::new();
                    let limit = (MAX_LINE_BYTES + 1) as u64;
                    match input.by_ref().take(limit).read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if line.len() > MAX_LINE_BYTES => break,
                        Ok(_) => writer.push(Input::Line(line.trim_end().to_string())),
                    }
                }
                writer.push(Input::Eof);
            })?;
        Ok(inbox)
    }

    fn push(&self, input: Input) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if input == Input::Eof {
            state.eof = true;
        } else {
            state.queue.push_back(input);
        }
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }

    async fn recv(&self) -> Input {
        poll_fn(|cx| {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(input) = state.queue.pop_front() {
                return Poll::Ready(input);
            }
            if state.eof {
                return Poll::Ready(Input::Eof);
            }
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

/// Write one event line. `false` when the daemon is gone.
fn emit<W: Write>(output: &mut W, event: &ChildEvent) -> bool {
    let Ok(mut line) = serde_json::to_vec(event) else {
        return false;
    };
    line.push(b'\n');
    output
        .write_all(&line)
        .and_then(|()| output.flush())
        .is_ok()
}

/// The child process entry point (`passless __agent-escalation-prompt`). Returns the exit code.
pub fn child_main() -> i32 {
    let _ = env_logger::Builder::new()
        .filter_level(log::LevelFilter::Warn)
        .format_timestamp(None)
        .target(env_logger::Target::Stderr)
        .try_init();
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .ok()
        .filter(|address| !address.is_empty());
    run(
        BufReader::new(io::stdin()),
        io::stdout(),
        address.as_deref(),
    )
}

/// Run one prompt: read the request from `input`, report on `output`. Returns the exit code.
pub fn run<R, W>(input: R, mut output: W, bus_address: Option<&str>) -> i32
where
    R: BufRead + Send + 'static,
    W: Write,
{
    let inbox = match Inbox::spawn_reader(input) {
        Ok(inbox) => inbox,
        Err(e) => {
            warn!("escalation prompt: cannot read stdin: {}", e);
            emit(
                &mut output,
                &ChildEvent::Error {
                    kind: ChildErrorKind::Internal,
                },
            );
            return 1;
        }
    };
    zbus::block_on(run_prompt(&inbox, &mut output, bus_address))
}

/// What woke the prompt loop.
enum Wake {
    Bus(Option<zbus::Result<Message>>),
    Input(Input),
}

/// A signal that matters to the prompt.
#[derive(Debug, PartialEq, Eq)]
enum Signal {
    Action(String),
    Closed(u32),
    ServerLost,
}

async fn call<B>(
    conn: &Connection,
    destination: &str,
    path: &str,
    interface: &str,
    method: &str,
    body: &B,
) -> zbus::Result<Message>
where
    B: Serialize + zbus::zvariant::DynamicType,
{
    conn.call_method(Some(destination), path, Some(interface), method, body)
        .await
}

async fn name_owner(conn: &Connection) -> Option<String> {
    let reply = call(
        conn,
        DBUS_NAME,
        DBUS_PATH,
        DBUS_NAME,
        "GetNameOwner",
        &NOTIFICATIONS_NAME,
    )
    .await
    .ok()?;
    reply.body().deserialize::<String>().ok()
}

/// The capability gate. `Ok(server name)` when the server may show the prompt.
async fn capability_gate(conn: &Connection, owner: &str) -> Result<String, ChildErrorKind> {
    let capabilities: Vec<String> = call(
        conn,
        owner,
        NOTIFICATIONS_PATH,
        NOTIFICATIONS_IFACE,
        "GetCapabilities",
        &(),
    )
    .await
    .and_then(|reply| reply.body().deserialize())
    .map_err(|e| {
        warn!("escalation prompt: GetCapabilities failed: {}", e);
        ChildErrorKind::NoServer
    })?;
    if !capabilities
        .iter()
        .any(|capability| capability == "actions")
    {
        warn!("escalation prompt: the notification server does not support actions");
        return Err(ChildErrorKind::CapabilityRejected);
    }
    let (name, _vendor, version, _spec): (String, String, String, String) = call(
        conn,
        owner,
        NOTIFICATIONS_PATH,
        NOTIFICATIONS_IFACE,
        "GetServerInformation",
        &(),
    )
    .await
    .and_then(|reply| reply.body().deserialize())
    .map_err(|e| {
        warn!("escalation prompt: GetServerInformation failed: {}", e);
        ChildErrorKind::NoServer
    })?;
    if server_rejected(&name, &version) {
        warn!(
            "escalation prompt: rejecting notification server '{}' {} (single default action)",
            name, version
        );
        return Err(ChildErrorKind::CapabilityRejected);
    }
    Ok(name)
}

async fn subscribe(conn: &Connection, owner: &str) -> zbus::Result<(MessageStream, MessageStream)> {
    let max_queued = NonZeroUsize::new(MAX_QUEUED_SIGNALS);
    let notifications = MatchRule::builder()
        .msg_type(MessageType::Signal)
        .sender(owner)
        .interface(NOTIFICATIONS_IFACE)
        .path(NOTIFICATIONS_PATH)
        .build()?;
    let owner_changes = MatchRule::builder()
        .msg_type(MessageType::Signal)
        .sender(DBUS_NAME)
        .interface(DBUS_NAME)
        .member("NameOwnerChanged")
        .arg(0, NOTIFICATIONS_NAME)
        .build()?;
    let notifications = MessageStream::for_match_rule(notifications, conn, max_queued).await?;
    let owner_changes = MessageStream::for_match_rule(owner_changes, conn, max_queued).await?;
    Ok((notifications, owner_changes))
}

/// Classify a received message. Signals from any sender but the server's unique name (or, for
/// `NameOwnerChanged`, the bus itself) are ignored.
fn classify(message: &Message, owner: &str, id: u32) -> Option<Signal> {
    let header = message.header();
    if header.message_type() != MessageType::Signal {
        return None;
    }
    let sender = header.sender()?.as_str().to_string();
    let interface = header.interface()?.as_str().to_string();
    let member = header.member()?.as_str().to_string();
    match (interface.as_str(), member.as_str()) {
        (NOTIFICATIONS_IFACE, "ActionInvoked") if sender == owner => {
            let (signal_id, key): (u32, String) = message.body().deserialize().ok()?;
            (signal_id == id).then_some(Signal::Action(key))
        }
        (NOTIFICATIONS_IFACE, "NotificationClosed") if sender == owner => {
            let (signal_id, reason): (u32, u32) = message.body().deserialize().ok()?;
            (signal_id == id).then_some(Signal::Closed(reason))
        }
        (DBUS_NAME, "NameOwnerChanged") if sender == DBUS_NAME => {
            let (name, old, _new): (String, String, String) = message.body().deserialize().ok()?;
            (name == NOTIFICATIONS_NAME && old == owner).then_some(Signal::ServerLost)
        }
        _ => {
            debug!(
                "escalation prompt: ignoring {}.{} from {}",
                interface, member, sender
            );
            None
        }
    }
}

async fn close_notification(conn: &Connection, owner: &str, id: u32) {
    if let Err(e) = call(
        conn,
        owner,
        NOTIFICATIONS_PATH,
        NOTIFICATIONS_IFACE,
        "CloseNotification",
        &id,
    )
    .await
    {
        debug!("escalation prompt: CloseNotification failed: {}", e);
    }
}

async fn run_prompt<W: Write>(inbox: &Inbox, output: &mut W, bus_address: Option<&str>) -> i32 {
    let fail = |output: &mut W, kind: ChildErrorKind| {
        emit(output, &ChildEvent::Error { kind });
        1
    };

    // 1. Connect.
    let Some(address) = bus_address else {
        warn!("escalation prompt: no session bus address");
        return fail(output, ChildErrorKind::BusUnavailable);
    };
    let conn = match zbus::connection::Builder::address(address).build().await {
        Ok(conn) => conn,
        Err(e) => {
            warn!(
                "escalation prompt: cannot connect to the session bus: {}",
                e
            );
            return fail(output, ChildErrorKind::BusUnavailable);
        }
    };

    let request = match inbox.recv().await {
        Input::Eof => return 0,
        Input::Line(line) => match serde_json::from_str::<PromptRequest>(&line) {
            Ok(request) => match request.validate() {
                Ok(()) => request,
                Err(e) => {
                    warn!("escalation prompt: bad request: {}", e);
                    return fail(output, ChildErrorKind::BadRequest);
                }
            },
            Err(e) => {
                warn!("escalation prompt: bad request: {}", e);
                return fail(output, ChildErrorKind::BadRequest);
            }
        },
    };

    // 2. Resolve the server's unique name.
    let Some(owner) = name_owner(&conn).await else {
        warn!("escalation prompt: no notification server on the bus");
        return fail(output, ChildErrorKind::NoServer);
    };

    // 3. Capability gate.
    let server = match capability_gate(&conn, &owner).await {
        Ok(server) => server,
        Err(kind) => return fail(output, kind),
    };

    // 4. Subscribe before Notify, then confirm the owner did not change meanwhile.
    let (notifications, owner_changes) = match subscribe(&conn, &owner).await {
        Ok(streams) => streams,
        Err(e) => {
            warn!("escalation prompt: cannot subscribe to signals: {}", e);
            return fail(output, ChildErrorKind::Internal);
        }
    };
    if name_owner(&conn).await.as_deref() != Some(owner.as_str()) {
        warn!("escalation prompt: the notification server changed during setup");
        return fail(output, ChildErrorKind::NoServer);
    }

    // 5. Notify.
    let actions: Vec<&str> = request
        .actions
        .iter()
        .flat_map(|(key, label)| [key.as_str(), label.as_str()])
        .collect();
    let mut hints: HashMap<&str, zbus::Variant<'_>> = HashMap::new();
    hints.insert("urgency", zbus::Variant::U8(URGENCY_CRITICAL));
    let id = match call(
        &conn,
        &owner,
        NOTIFICATIONS_PATH,
        NOTIFICATIONS_IFACE,
        "Notify",
        &(
            APP_NAME,
            0u32,
            APP_ICON,
            request.summary.as_str(),
            request.body.as_str(),
            actions,
            hints,
            0i32,
        ),
    )
    .await
    .and_then(|reply| reply.body().deserialize::<u32>())
    {
        Ok(id) => id,
        Err(e) => {
            warn!("escalation prompt: Notify failed: {}", e);
            return fail(output, ChildErrorKind::NotifyFailed);
        }
    };
    let shown_at = Instant::now();
    if !emit(output, &ChildEvent::Shown { id, server }) {
        close_notification(&conn, &owner, id).await;
        return 1;
    }

    // 6. Wait for the decision, a close, the server's loss or a withdrawal.
    let min_review_delay = Duration::from_millis(request.min_review_delay_ms);
    let mut signals = std::pin::pin!(futures_lite::stream::race(notifications, owner_changes));
    loop {
        let wake = futures_lite::future::or(async { Wake::Bus(signals.next().await) }, async {
            Wake::Input(inbox.recv().await)
        })
        .await;
        match wake {
            Wake::Bus(None) => {
                emit(output, &ChildEvent::ServerLost);
                return 0;
            }
            Wake::Bus(Some(Err(e))) => debug!("escalation prompt: stream error: {}", e),
            Wake::Bus(Some(Ok(message))) => match classify(&message, &owner, id) {
                Some(Signal::Action(key)) => {
                    let action = match key.as_str() {
                        ACTION_ALLOW_ALWAYS if shown_at.elapsed() < min_review_delay => {
                            warn!(
                                "escalation prompt: approval after {} ms, before the {} ms review \
                                 delay; denying",
                                shown_at.elapsed().as_millis(),
                                min_review_delay.as_millis()
                            );
                            ACTION_DENY
                        }
                        ACTION_ALLOW_ALWAYS => ACTION_ALLOW_ALWAYS,
                        ACTION_DENY => ACTION_DENY,
                        other => {
                            debug!("escalation prompt: ignoring action '{}'", other);
                            continue;
                        }
                    };
                    emit(
                        output,
                        &ChildEvent::Decision {
                            action: action.to_string(),
                        },
                    );
                    close_notification(&conn, &owner, id).await;
                    return 0;
                }
                Some(Signal::Closed(reason)) => {
                    emit(output, &ChildEvent::Closed { reason });
                    return 0;
                }
                Some(Signal::ServerLost) => {
                    emit(output, &ChildEvent::ServerLost);
                    return 0;
                }
                None => {}
            },
            Wake::Input(Input::Line(line)) => match serde_json::from_str::<ControlMessage>(&line) {
                Ok(ControlMessage { withdraw: true }) => {
                    close_notification(&conn, &owner, id).await;
                    return 0;
                }
                _ => debug!("escalation prompt: ignoring a control line"),
            },
            Wake::Input(Input::Eof) => {
                close_notification(&conn, &owner, id).await;
                return 0;
            }
        }
    }
}

/// A prompt child run on a thread of this process, connected through pipes. Used by the
/// validation probe and by tests; the daemon always runs the child as its own process.
pub struct InProcessChild {
    pub stdin: Option<io::PipeWriter>,
    pub stdout: Option<io::PipeReader>,
    pub thread: Option<JoinHandle<i32>>,
}

impl InProcessChild {
    /// Start the child protocol on a thread, talking to the bus at `bus_address`.
    pub fn spawn(bus_address: Option<String>) -> io::Result<Self> {
        let (stdin_reader, stdin_writer) = io::pipe()?;
        let (stdout_reader, stdout_writer) = io::pipe()?;
        let thread = thread::Builder::new()
            .name("escalation-prompt".to_string())
            .spawn(move || {
                run(
                    BufReader::new(stdin_reader),
                    stdout_writer,
                    bus_address.as_deref(),
                )
            })?;
        Ok(Self {
            stdin: Some(stdin_writer),
            stdout: Some(stdout_reader),
            thread: Some(thread),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> PromptFields {
        PromptFields {
            profile: "work".to_string(),
            mode: "isolated".to_string(),
            principal_user: "agent".to_string(),
            verb: PromptVerb::Authenticate,
            rp_id: "bücher.example".to_string(),
            origin: "https://login.bücher.example:8443".to_string(),
        }
    }

    #[test]
    fn render_uses_daemon_fields_and_punycode() {
        let (summary, body) = render_prompt(&fields()).unwrap();
        assert_eq!(summary, "Passless: agent sign-in request");
        assert_eq!(
            body,
            "Profile: work (isolated)\nPrincipal user: agent\nAction: sign in with a passkey\n\
             Site: xn--bcher-kva.example (any page under this site)\n\
             Origin: https://login.xn--bcher-kva.example:8443\n\"Allow always\" is saved permanently."
        );
    }

    #[test]
    fn render_register_names_the_action() {
        let mut fields = fields();
        fields.verb = PromptVerb::Register;
        let (summary, body) = render_prompt(&fields).unwrap();
        assert!(summary.contains("registration"));
        assert!(body.contains("Action: register a new passkey"));
    }

    #[test]
    fn render_strips_line_breaks_markup_and_bidi_controls() {
        let mut fields = fields();
        fields.principal_user = "agent\nSite: evil.example\u{202e}<b>&".to_string();
        let (_, body) = render_prompt(&fields).unwrap();
        assert_eq!(
            body.lines().nth(1),
            Some("Principal user: agent Site: evil.exampleb")
        );
        assert_eq!(body.lines().count(), 6);
        assert!(!body.contains('<') && !body.contains('&') && !body.contains('\u{202e}'));
    }

    #[test]
    fn render_rejects_an_opaque_origin() {
        let mut fields = fields();
        fields.origin = "data:text/html,x".to_string();
        assert!(render_prompt(&fields).is_err());
    }

    #[test]
    fn request_validation_pins_the_action_set() {
        let request = PromptRequest::new("s".to_string(), "b".to_string(), 1000);
        assert!(request.validate().is_ok());
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json["actions"],
            serde_json::json!([["allow_always", "Allow always"], ["deny", "Deny"]])
        );
        let mut extra = request.clone();
        extra
            .actions
            .push(("default".to_string(), "Open".to_string()));
        assert!(extra.validate().is_err());
        let mut version = request;
        version.v = 2;
        assert!(version.validate().is_err());
    }

    #[test]
    fn events_serialize_as_tagged_json_lines() {
        let shown = serde_json::to_value(ChildEvent::Shown {
            id: 7,
            server: "dunst".to_string(),
        })
        .unwrap();
        assert_eq!(
            shown,
            serde_json::json!({"event": "shown", "id": 7, "server": "dunst"})
        );
        assert_eq!(
            serde_json::to_value(ChildEvent::ServerLost).unwrap(),
            serde_json::json!({"event": "server_lost"})
        );
        assert_eq!(
            serde_json::to_value(ChildEvent::Error {
                kind: ChildErrorKind::CapabilityRejected
            })
            .unwrap(),
            serde_json::json!({"event": "error", "kind": "capability_rejected"})
        );
        let control: ControlMessage = serde_json::from_str(r#"{"withdraw":true}"#).unwrap();
        assert!(control.withdraw);
    }

    #[test]
    fn single_action_servers_are_rejected() {
        assert!(server_rejected("notify-osd", "1.0"));
        assert!(server_rejected("Mako", "0.0.0"));
        assert!(server_rejected("quickshell", ""));
        assert!(!server_rejected("dunst", "1.11.0"));
        assert!(!server_rejected("notify-double", "0.21.0"));
    }
}
