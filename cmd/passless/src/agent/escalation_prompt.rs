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
//! 3. capability gate ([`server_support`]): the server must advertise `actions`, or be notify-osd
//!    1.0, which shows distinct buttons in a fallback dialog; known single-action servers are
//!    rejected;
//! 4. subscribe to `ActionInvoked`/`NotificationClosed` filtered on that unique sender, and to
//!    `NameOwnerChanged` for the well-known name, all before `Notify`;
//! 5. `Notify` with `expire_timeout = 0`, critical urgency and exactly two actions: for a sign-in
//!    prompt "Allow always" and "Deny", for a registration prompt "Register once" and "Deny"
//!    (ADR 0014 amendment section 5), whose keys are `allow_always:<nonce>` (or
//!    `register_once:<nonce>`) and `deny:<nonce>` with a fresh 128-bit nonce per prompt (the labels
//!    never show it);
//! 6. report `shown`, then exactly one of `decision`, `closed` or `server_lost` and exit. A
//!    `{"withdraw":true}` line or EOF on stdin closes the notification (`CloseNotification`) and
//!    exits. The child has no prompt timeout of its own: the daemon withdraws it.
//!
//! Attribution. Only `ActionInvoked` decides, and only when its sender is the server's unique name,
//! its id is this prompt's id and its key is exactly one of this prompt's two keys. notify-osd
//! returns id 0 for every fallback dialog, so the id alone cannot tell concurrent prompts (other
//! RPs, other profiles) apart, nor a stale dialog of a withdrawn prompt from a live one; the
//! per-prompt keys do. A click on a dialog whose child has exited (withdrawn, timed out, denied
//! into cooldown, daemon restarted) matches no live prompt and grants nothing. With a shared id 0
//! a `NotificationClosed` cannot be attributed either: it is ignored, and the prompt waits for its
//! action or the daemon's withdrawal; `CloseNotification(0)` is not sent, so a withdrawn dialog may
//! stay visible (inert).
//!
//! Protocol version 2 (JSON lines). Daemon to child: first
//! `{"v":2,"summary":…,"body":…,"actions":[["allow_always","Allow always"],["deny","Deny"]],"min_review_delay_ms":…}`
//! (or `[["register_once","Register once"],["deny","Deny"]]` for a registration prompt; no other
//! action set is accepted), later `{"withdraw":true}` or EOF. Child to daemon:
//! `{"event":"shown","id":…,"server":…}`, `{"event":"decision","action":…}`,
//! `{"event":"closed","reason":…}`, `{"event":"server_lost"}`, `{"event":"error","kind":…}`.
//!
//! The request and the `decision` event carry the bare keys (`allow_always` or `register_once`,
//! and `deny`): the nonce never leaves the child. Only the approving key of the request's own
//! action set is ever sent to the server, so only it can come back.
//!
//! An approval that arrives before `min_review_delay_ms` has passed since `Notify` returned is
//! reported as a `deny` decision. The daemon applies the same rule against its own clock, and
//! accepts `register_once` only for a registration prompt and `allow_always` only for a sign-in
//! prompt.
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
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zbus::message::Type as MessageType;
use zbus::{Connection, MatchRule, Message, MessageStream};

/// The hidden first argument that turns the daemon binary into a prompt child.
pub const HIDDEN_ARG: &str = "__agent-escalation-prompt";
/// Version 2 (ADR 0014 amendment section 5.4): a registration prompt has its own action set.
pub const PROTOCOL_VERSION: u32 = 2;
pub const ACTION_ALLOW_ALWAYS: &str = "allow_always";
/// The approving action of a registration prompt: one registration, not a standing grant.
pub const ACTION_REGISTER_ONCE: &str = "register_once";
pub const ACTION_DENY: &str = "deny";
pub const LABEL_ALLOW_ALWAYS: &str = "Allow always";
pub const LABEL_REGISTER_ONCE: &str = "Register once";
pub const LABEL_DENY: &str = "Deny";
/// The minimum review delay: an earlier approval is a deny (a heuristic, not authentication;
/// ADR 0014 section 8.2).
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
/// The id notify-osd returns for every fallback dialog. The specification never assigns 0, so a
/// notification with this id is not addressable: its closes cannot be attributed and
/// `CloseNotification` cannot target it.
const SHARED_NOTIFICATION_ID: u32 = 0;
/// Bytes of randomness in a prompt's action-key nonce.
const NONCE_BYTES: usize = 16;

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
    /// A request with the action set of `verb`, the only one allowed for it.
    pub fn new(verb: PromptVerb, summary: String, body: String, min_review_delay_ms: u64) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            summary,
            body,
            actions: allowed_actions(verb),
            min_review_delay_ms,
        }
    }

    /// The approving action of this request's action set (`allow_always` or `register_once`),
    /// if the set is one of the two allowed ones.
    pub fn approve_action(&self) -> Option<&'static str> {
        [PromptVerb::Authenticate, PromptVerb::Register]
            .into_iter()
            .find(|verb| self.actions == allowed_actions(*verb))
            .map(PromptVerb::approve_action)
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.v != PROTOCOL_VERSION {
            return Err("unsupported protocol version");
        }
        if self.approve_action().is_none() {
            return Err(
                "the actions must be exactly allow_always and deny, or register_once and deny",
            );
        }
        if self.summary.is_empty() {
            return Err("empty summary");
        }
        Ok(())
    }
}

/// The one action set a prompt for `verb` may carry.
fn allowed_actions(verb: PromptVerb) -> Vec<(String, String)> {
    let (approve, label) = match verb {
        PromptVerb::Authenticate => (ACTION_ALLOW_ALWAYS, LABEL_ALLOW_ALWAYS),
        PromptVerb::Register => (ACTION_REGISTER_ONCE, LABEL_REGISTER_ONCE),
    };
    vec![
        (approve.to_string(), label.to_string()),
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
///
/// notify-osd is not on this list any more. It was listed because it lacks the `actions`
/// capability, but on Ubuntu notify-osd 1.0 ("Canonical Ltd", spec 1.1) a `Notify` with the
/// actions `allow_always`/"Allow always" and `deny`/"Deny", urgency 2 and timeout 0 showed a
/// fallback dialog with both buttons, and clicking "Deny" emitted `ActionInvoked(0, "deny")` then
/// `NotificationClosed(0, 3)` from notify-osd's unique name: the keys stay distinct. It is accepted
/// by [`notify_osd_fallback_dialog`]. No such evidence exists for mako 0.0.0 and quickshell, so
/// they stay rejected.
pub fn server_rejected(name: &str, version: &str) -> bool {
    matches!(
        (name.to_lowercase().as_str(), version),
        ("mako", "0.0.0") | ("quickshell", "")
    )
}

/// Whether the server is the notify-osd whose fallback dialog was verified to deliver the distinct
/// action keys (see [`server_rejected`]). Matched on name and exact version: another notify-osd
/// version without `actions` is not assumed to behave the same.
pub fn notify_osd_fallback_dialog(name: &str, version: &str) -> bool {
    name.eq_ignore_ascii_case("notify-osd") && version == "1.0"
}

/// How a notification server can show an escalation prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSupport {
    /// It advertises `actions`.
    Actions,
    /// notify-osd 1.0: no `actions` capability, but a fallback dialog with distinct buttons whose
    /// `Notify` returns the shared id 0.
    FallbackDialog,
}

/// The capability gate, shared by the prompt child and `passless doctor --agents`: whether the
/// server named `name` `version` with `capabilities` can show an escalation prompt with two
/// distinct actions. `Err` says why not.
pub fn server_support(
    name: &str,
    version: &str,
    capabilities: &[String],
) -> Result<ServerSupport, &'static str> {
    if server_rejected(name, version) {
        return Err("the notification server collapses actions into one default action");
    }
    if capabilities
        .iter()
        .any(|capability| capability == "actions")
    {
        return Ok(ServerSupport::Actions);
    }
    if notify_osd_fallback_dialog(name, version) {
        return Ok(ServerSupport::FallbackDialog);
    }
    Err("the notification server does not support actions")
}

/// This prompt's two action keys: `<key>:<nonce>` for its approving action (`allow_always` or
/// `register_once`) and for `deny`. The other approving key is never generated, so it can neither
/// be sent to the server nor decoded.
struct PromptKeys {
    /// The bare approving action of this prompt.
    approve_action: &'static str,
    approve: String,
    deny: String,
}

impl PromptKeys {
    /// Fresh keys for a prompt approved by `approve_action`, from the OS random source. `None`
    /// if it fails or the action is not an approving one.
    fn generate(approve_action: &str) -> Option<Self> {
        let approve_action = match approve_action {
            ACTION_ALLOW_ALWAYS => ACTION_ALLOW_ALWAYS,
            ACTION_REGISTER_ONCE => ACTION_REGISTER_ONCE,
            _ => return None,
        };
        let mut bytes = [0u8; NONCE_BYTES];
        OsRng.try_fill_bytes(&mut bytes).ok()?;
        let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Some(Self {
            approve_action,
            approve: format!("{approve_action}:{nonce}"),
            deny: format!("{ACTION_DENY}:{nonce}"),
        })
    }

    /// The key sent to the server for the bare request key `key`.
    fn wire(&self, key: &str) -> Option<&str> {
        if key == self.approve_action {
            Some(&self.approve)
        } else if key == ACTION_DENY {
            Some(&self.deny)
        } else {
            None
        }
    }

    /// The bare action of a received key: only an exact match of this prompt's keys.
    fn decode(&self, key: &str) -> Option<&'static str> {
        if key == self.approve {
            Some(self.approve_action)
        } else if key == self.deny {
            Some(ACTION_DENY)
        } else {
            None
        }
    }
}

/// The verb of the prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptVerb {
    Authenticate,
    Register,
}

impl PromptVerb {
    /// The bare key of the action that approves a prompt of this verb.
    pub fn approve_action(self) -> &'static str {
        match self {
            Self::Authenticate => ACTION_ALLOW_ALWAYS,
            Self::Register => ACTION_REGISTER_ONCE,
        }
    }
}

/// Which configured rule made the prompt necessary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptRule {
    /// The site's own (exact) rule.
    Exact,
    /// The `*` rule: the site is not on the operator's list.
    Wildcard,
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
    /// The validated origin; rendered in its ASCII serialization. `None` for a pre-request no
    /// page is behind (ADR 0014 amendment section 2.3): rendered as `none yet`.
    pub origin: Option<String>,
    /// The agent asked in advance (`RequestAccess`): the body says that no page is waiting
    /// (amendment sections 5.1 and 5.3). Nothing the agent supplied is shown.
    pub requested_in_advance: bool,
    /// The rule that resolved to `request`.
    pub rule: PromptRule,
    /// Registration only: how many passkeys the target store holds for the RP, when the backend
    /// can count them without decrypting (amendment section 5.2). `None` omits the clause.
    pub store_count: Option<usize>,
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
pub(crate) fn sanitize_line(input: &str, max_bytes: usize) -> String {
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

/// The registration summary (ADR 0014 amendment section 5.1).
pub const REGISTER_SUMMARY: &str = "Passless: CREATE A NEW PASSKEY? (not a sign-in)";

/// The store-count clause of the registration prompt's "Stored in" line.
fn store_count_clause(count: Option<usize>) -> String {
    match count {
        None => String::new(),
        Some(0) => ", which holds no passkey for this site yet".to_string(),
        Some(1) => ", which already holds 1 passkey for this site".to_string(),
        Some(n) => format!(", which already holds {n} passkeys for this site"),
    }
}

/// What the origin line shows: the validated origin, or `none yet` for a pre-request.
fn origin_line(origin: Option<&str>) -> Result<String, String> {
    match origin {
        Some(origin) => Ok(sanitize_line(&ascii_origin(origin)?, 300)),
        None => Ok(ORIGIN_NONE_YET.to_string()),
    }
}

/// The origin line of a pre-request prompt (ADR 0014 amendment sections 5.1 and 5.3).
pub const ORIGIN_NONE_YET: &str = "none yet";
/// Who asked, on a pre-request prompt (amendment sections 5.1 and 5.3).
pub const REQUESTED_IN_ADVANCE: &str = "the agent in advance (no page is waiting)";

/// The registration prompt (ADR 0014 amendment section 5.1): six lines, each a daemon-derived
/// fact; the summary says it is not a sign-in.
fn render_registration(fields: &PromptFields, rp_id: &str, origin: &str) -> (String, String) {
    let site = match fields.rule {
        PromptRule::Exact => "your rule for this site",
        PromptRule::Wildcard => "NOT on your list; matched by the * rule",
    };
    let profile = sanitize_line(&fields.profile, 128);
    // Anything but an isolated profile writes to the human's own store: say so.
    let store = if fields.mode == "isolated" {
        format!("the agent's own store (isolated profile \"{profile}\")")
    } else {
        format!(
            "YOUR passkey store ({} profile \"{profile}\")",
            sanitize_line(&fields.mode, 32)
        )
    };
    let body = format!(
        "Action: create a new passkey and register it at this site\n\
         Site: {} ({})\n\
         Origin: {}\n\
         Stored in: {}{}\n\
         Approving allows this one registration, then lets the agent sign in here without asking.\n\
         Requested by: {}, principal user {}",
        sanitize_line(rp_id, 253),
        site,
        origin,
        store,
        store_count_clause(fields.store_count),
        if fields.requested_in_advance {
            REQUESTED_IN_ADVANCE
        } else {
            "a page now"
        },
        sanitize_line(&fields.principal_user, 64),
    );
    (REGISTER_SUMMARY.to_string(), body)
}

/// The notification summary and body built from daemon-derived fields only.
pub fn render_prompt(fields: &PromptFields) -> Result<(String, String), String> {
    let rp_id = ascii_rp_id(&fields.rp_id)?;
    let origin = origin_line(fields.origin.as_deref())?;
    let (summary, action) = match fields.verb {
        PromptVerb::Authenticate => ("Passless: agent sign-in request", "sign in with a passkey"),
        PromptVerb::Register => return Ok(render_registration(fields, &rp_id, &origin)),
    };
    // A pre-request adds one daemon-derived line (amendment section 5.3): seven in all, which
    // still fits notify-osd's fallback dialog.
    let requested_by = if fields.requested_in_advance {
        format!("Requested by: {REQUESTED_IN_ADVANCE}\n")
    } else {
        String::new()
    };
    let body = format!(
        "Profile: {} ({})\nPrincipal user: {}\nAction: {}\nSite: {} (any page under this site)\nOrigin: {}\n{}\"Allow always\" is saved permanently.",
        sanitize_line(&fields.profile, 128),
        sanitize_line(&fields.mode, 32),
        sanitize_line(&fields.principal_user, 64),
        action,
        sanitize_line(&rp_id, 253),
        origin,
        requested_by,
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
    match server_support(&name, &version, &capabilities) {
        Ok(ServerSupport::Actions) => Ok(name),
        Ok(ServerSupport::FallbackDialog) => {
            debug!(
                "escalation prompt: '{}' {} has no actions capability; using its fallback dialog",
                name, version
            );
            Ok(name)
        }
        Err(why) => {
            warn!(
                "escalation prompt: rejecting notification server '{}' {}: {}",
                name, version, why
            );
            Err(ChildErrorKind::CapabilityRejected)
        }
    }
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
/// `NameOwnerChanged`, the bus itself) are ignored. The action key is checked by the caller.
/// A `NotificationClosed` for the shared id 0 is ignored: it may be any dialog's (a stale one of a
/// withdrawn prompt, another profile's), so it cannot end this prompt.
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
            if id == SHARED_NOTIFICATION_ID {
                debug!(
                    "escalation prompt: ignoring NotificationClosed for the shared id (reason {})",
                    reason
                );
                return None;
            }
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

/// Close the notification. Not for the shared id 0, which addresses no notification of ours (and
/// on notify-osd closes no dialog): that dialog stays visible but inert, since no live prompt
/// holds its keys.
async fn close_notification(conn: &Connection, owner: &str, id: u32) {
    if id == SHARED_NOTIFICATION_ID {
        debug!("escalation prompt: the shared-id dialog cannot be closed; it stays inert");
        return;
    }
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

    // 5. Notify, with this prompt's own action keys.
    let Some(approve_action) = request.approve_action() else {
        return fail(output, ChildErrorKind::BadRequest);
    };
    let Some(keys) = PromptKeys::generate(approve_action) else {
        warn!("escalation prompt: no randomness for the action keys");
        return fail(output, ChildErrorKind::Internal);
    };
    let mut actions: Vec<&str> = Vec::with_capacity(request.actions.len() * 2);
    for (key, label) in &request.actions {
        let Some(wire) = keys.wire(key) else {
            return fail(output, ChildErrorKind::BadRequest);
        };
        actions.extend([wire, label.as_str()]);
    }
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
                    // Only this prompt's exact keys decide: a bare, foreign or stale key (another
                    // prompt's dialog sharing id 0, a dialog left from a withdrawn prompt) is
                    // ignored, and the prompt keeps waiting.
                    let Some(action) = keys.decode(&key) else {
                        debug!("escalation prompt: ignoring an action key of another prompt");
                        continue;
                    };
                    let action = match action {
                        ACTION_ALLOW_ALWAYS | ACTION_REGISTER_ONCE
                            if shown_at.elapsed() < min_review_delay =>
                        {
                            warn!(
                                "escalation prompt: approval after {} ms, before the {} ms review \
                                 delay; denying",
                                shown_at.elapsed().as_millis(),
                                min_review_delay.as_millis()
                            );
                            ACTION_DENY
                        }
                        other => other,
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
            origin: Some("https://login.bücher.example:8443".to_string()),
            requested_in_advance: false,
            rule: PromptRule::Exact,
            store_count: Some(3),
        }
    }

    fn registration(mode: &str, rule: PromptRule, store_count: Option<usize>) -> PromptFields {
        PromptFields {
            profile: "coding".to_string(),
            mode: mode.to_string(),
            principal_user: "alice".to_string(),
            verb: PromptVerb::Register,
            rp_id: "example.org".to_string(),
            origin: Some("https://www.example.org".to_string()),
            requested_in_advance: false,
            rule,
            store_count,
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
    fn render_sign_in_ignores_the_registration_fields() {
        // The sign-in prompt is unchanged (amendment section 5.3): no rule or count line.
        let mut wildcard = fields();
        wildcard.rule = PromptRule::Wildcard;
        wildcard.store_count = None;
        assert_eq!(render_prompt(&wildcard), render_prompt(&fields()));
    }

    #[test]
    fn render_wildcard_registration_matches_the_amendment_text() {
        let (summary, body) =
            render_prompt(&registration("same-user", PromptRule::Wildcard, Some(1))).unwrap();
        assert_eq!(summary, "Passless: CREATE A NEW PASSKEY? (not a sign-in)");
        assert_eq!(
            body,
            "Action: create a new passkey and register it at this site\n\
             Site: example.org (NOT on your list; matched by the * rule)\n\
             Origin: https://www.example.org\n\
             Stored in: YOUR passkey store (same-user profile \"coding\"), which already holds 1 passkey for this site\n\
             Approving allows this one registration, then lets the agent sign in here without asking.\n\
             Requested by: a page now, principal user alice"
        );
        // notify-osd's fallback dialog has room for seven lines.
        assert!(body.lines().count() <= 7);
        assert!(!body.contains("Allow always"));
    }

    #[test]
    fn render_registration_variants_of_rule_store_and_count() {
        let line = |fields: PromptFields, prefix: &str| {
            let (_, body) = render_prompt(&fields).unwrap();
            body.lines()
                .find(|line| line.starts_with(prefix))
                .unwrap()
                .to_string()
        };
        assert_eq!(
            line(registration("same-user", PromptRule::Exact, None), "Site:"),
            "Site: example.org (your rule for this site)"
        );
        assert_eq!(
            line(
                registration("isolated", PromptRule::Exact, None),
                "Stored in:"
            ),
            "Stored in: the agent's own store (isolated profile \"coding\")"
        );
        // The count clause in its three forms ...
        for (count, clause) in [
            (Some(0), ", which holds no passkey for this site yet"),
            (Some(1), ", which already holds 1 passkey for this site"),
            (Some(2), ", which already holds 2 passkeys for this site"),
            (Some(17), ", which already holds 17 passkeys for this site"),
        ] {
            assert_eq!(
                line(
                    registration("same-user", PromptRule::Wildcard, count),
                    "Stored in:"
                ),
                format!("Stored in: YOUR passkey store (same-user profile \"coding\"){clause}"),
                "{count:?}"
            );
        }
        // ... and omitted entirely, never a 0, when the backend cannot count.
        let omitted = line(
            registration("same-user", PromptRule::Wildcard, None),
            "Stored in:",
        );
        assert_eq!(
            omitted,
            "Stored in: YOUR passkey store (same-user profile \"coding\")"
        );
        assert!(!omitted.contains("which"));
    }

    #[test]
    fn render_registration_sanitizes_its_fields() {
        let mut fields = registration("same-user", PromptRule::Wildcard, Some(1));
        fields.principal_user = "alice\nApproving is safe\u{202e}<b>".to_string();
        fields.profile = "co\nding".to_string();
        let (_, body) = render_prompt(&fields).unwrap();
        assert_eq!(body.lines().count(), 6);
        assert!(!body.contains('<') && !body.contains('\u{202e}'));
        assert!(body.ends_with("principal user alice Approving is safeb"));
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
    fn render_pre_request_sign_in_matches_the_amendment_lines() {
        let mut pre = fields();
        pre.origin = None;
        pre.requested_in_advance = true;
        let (summary, body) = render_prompt(&pre).unwrap();
        assert_eq!(summary, "Passless: agent sign-in request");
        assert_eq!(
            body,
            "Profile: work (isolated)\nPrincipal user: agent\nAction: sign in with a passkey\n\
             Site: xn--bcher-kva.example (any page under this site)\n\
             Origin: none yet\n\
             Requested by: the agent in advance (no page is waiting)\n\
             \"Allow always\" is saved permanently."
        );
        assert!(body.lines().count() <= 7);
    }

    #[test]
    fn render_pre_request_registration_matches_the_amendment_lines() {
        let mut pre = registration("same-user", PromptRule::Wildcard, Some(0));
        pre.origin = None;
        pre.requested_in_advance = true;
        let (summary, body) = render_prompt(&pre).unwrap();
        assert_eq!(summary, REGISTER_SUMMARY);
        assert_eq!(
            body,
            "Action: create a new passkey and register it at this site\n\
             Site: example.org (NOT on your list; matched by the * rule)\n\
             Origin: none yet\n\
             Stored in: YOUR passkey store (same-user profile \"coding\"), which holds no passkey for this site yet\n\
             Approving allows this one registration, then lets the agent sign in here without asking.\n\
             Requested by: the agent in advance (no page is waiting), principal user alice"
        );
        assert!(body.lines().count() <= 7);
        // A ceremony that adopted the pre-request before it was shown has a page: its origin.
        pre.origin = Some("https://www.example.org".to_string());
        let (_, body) = render_prompt(&pre).unwrap();
        assert!(body.contains("\nOrigin: https://www.example.org\n"));
    }

    #[test]
    fn render_rejects_an_opaque_origin() {
        let mut fields = fields();
        fields.origin = Some("data:text/html,x".to_string());
        assert!(render_prompt(&fields).is_err());
    }

    #[test]
    fn request_validation_pins_the_action_set_per_verb() {
        let request = PromptRequest::new(
            PromptVerb::Authenticate,
            "s".to_string(),
            "b".to_string(),
            1000,
        );
        assert!(request.validate().is_ok());
        assert_eq!(request.approve_action(), Some(ACTION_ALLOW_ALWAYS));
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["v"], 2);
        assert_eq!(
            json["actions"],
            serde_json::json!([["allow_always", "Allow always"], ["deny", "Deny"]])
        );

        let register =
            PromptRequest::new(PromptVerb::Register, "s".to_string(), "b".to_string(), 1000);
        assert!(register.validate().is_ok());
        assert_eq!(register.approve_action(), Some(ACTION_REGISTER_ONCE));
        assert_eq!(
            serde_json::to_value(&register).unwrap()["actions"],
            serde_json::json!([["register_once", "Register once"], ["deny", "Deny"]])
        );

        // Nothing else is accepted: an extra action, a mixed or relabelled set, three actions.
        let mut extra = request.clone();
        extra
            .actions
            .push(("default".to_string(), "Open".to_string()));
        assert!(extra.validate().is_err());
        let mut mixed = register.clone();
        mixed.actions[0].1 = LABEL_ALLOW_ALWAYS.to_string();
        assert!(mixed.validate().is_err());
        let mut both = request.clone();
        both.actions.insert(
            1,
            (
                ACTION_REGISTER_ONCE.to_string(),
                LABEL_REGISTER_ONCE.to_string(),
            ),
        );
        assert!(both.validate().is_err());
        assert_eq!(both.approve_action(), None);
        // Version 1 (one action set only) is refused.
        let mut version = request;
        version.v = 1;
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
        assert!(!server_rejected("notify-osd", "1.0"));
        assert!(server_rejected("Mako", "0.0.0"));
        assert!(server_rejected("quickshell", ""));
        assert!(!server_rejected("dunst", "1.11.0"));
        assert!(!server_rejected("notify-double", "0.21.0"));
    }

    fn caps(list: &[&str]) -> Vec<String> {
        list.iter().map(|c| c.to_string()).collect()
    }

    #[test]
    fn server_support_accepts_actions_and_the_notify_osd_dialog_only() {
        let notify_osd = caps(&[
            "body",
            "body-markup",
            "icon-static",
            "image/svg+xml",
            "x-canonical-private-synchronous",
            "x-canonical-append",
            "x-canonical-private-icon-only",
            "x-canonical-truncation",
            "private-synchronous",
            "append",
            "private-icon-only",
            "truncation",
        ]);
        assert_eq!(
            server_support("notify-osd", "1.0", &notify_osd),
            Ok(ServerSupport::FallbackDialog)
        );
        assert_eq!(
            server_support("Notify-OSD", "1.0", &notify_osd),
            Ok(ServerSupport::FallbackDialog)
        );
        // Another version, or another server, without `actions` is not assumed to have the dialog.
        assert!(server_support("notify-osd", "0.9.35", &notify_osd).is_err());
        assert!(server_support("notify-double", "1.0", &notify_osd).is_err());
        assert!(server_support("dunst", "1.11.0", &caps(&["body"])).is_err());
        assert_eq!(
            server_support("dunst", "1.11.0", &caps(&["actions", "body"])),
            Ok(ServerSupport::Actions)
        );
        // Known single-action servers stay rejected even when they advertise `actions`.
        assert!(server_support("mako", "0.0.0", &caps(&["actions"])).is_err());
        assert!(server_support("quickshell", "", &caps(&["actions"])).is_err());
    }

    #[test]
    fn registration_prompt_keys_are_distinct_and_nonced() {
        let keys = PromptKeys::generate(ACTION_REGISTER_ONCE).unwrap();
        let register = keys.wire(ACTION_REGISTER_ONCE).unwrap();
        let deny = keys.wire(ACTION_DENY).unwrap();
        let nonce = register.strip_prefix("register_once:").unwrap();
        assert_eq!(nonce.len(), NONCE_BYTES * 2);
        assert_eq!(deny, format!("deny:{nonce}"));
        assert_eq!(keys.decode(register), Some(ACTION_REGISTER_ONCE));
        assert_eq!(keys.decode(deny), Some(ACTION_DENY));
        // The sign-in key is never generated for a registration prompt: it can be neither sent
        // nor decoded, even with this prompt's own nonce.
        assert_eq!(keys.wire(ACTION_ALLOW_ALWAYS), None);
        assert_eq!(keys.decode(&format!("allow_always:{nonce}")), None);
        assert_eq!(keys.decode(ACTION_REGISTER_ONCE), None);
        // And the other way round.
        let sign_in = PromptKeys::generate(ACTION_ALLOW_ALWAYS).unwrap();
        assert_eq!(sign_in.wire(ACTION_REGISTER_ONCE), None);
        let sign_in_nonce = sign_in
            .wire(ACTION_ALLOW_ALWAYS)
            .unwrap()
            .strip_prefix("allow_always:")
            .unwrap()
            .to_string();
        assert_eq!(
            sign_in.decode(&format!("register_once:{sign_in_nonce}")),
            None
        );
        // Only approving actions have keys.
        assert!(PromptKeys::generate(ACTION_DENY).is_none());
        assert!(PromptKeys::generate("default").is_none());
    }

    #[test]
    fn prompt_keys_are_unique_per_prompt_and_match_exactly() {
        let a = PromptKeys::generate(ACTION_ALLOW_ALWAYS).unwrap();
        let b = PromptKeys::generate(ACTION_ALLOW_ALWAYS).unwrap();
        let allow = a.wire(ACTION_ALLOW_ALWAYS).unwrap();
        let deny = a.wire(ACTION_DENY).unwrap();
        let nonce = allow.strip_prefix("allow_always:").unwrap();
        assert_eq!(nonce.len(), NONCE_BYTES * 2);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(deny, format!("deny:{nonce}"));
        assert_ne!(allow, b.wire(ACTION_ALLOW_ALWAYS).unwrap());
        assert_eq!(a.wire("default"), None);

        assert_eq!(a.decode(allow), Some(ACTION_ALLOW_ALWAYS));
        assert_eq!(a.decode(deny), Some(ACTION_DENY));
        // Bare keys, another prompt's keys and near misses decide nothing.
        let misses: [String; 8] = [
            ACTION_ALLOW_ALWAYS.to_string(),
            ACTION_DENY.to_string(),
            b.wire(ACTION_ALLOW_ALWAYS).unwrap().to_string(),
            b.wire(ACTION_DENY).unwrap().to_string(),
            format!("{allow} "),
            allow[..allow.len() - 1].to_string(),
            format!("deny:{nonce}:"),
            "Allow always".to_string(),
        ];
        for key in &misses {
            assert_eq!(a.decode(key), None, "{key}");
        }
    }
}
