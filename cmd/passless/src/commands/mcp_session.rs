//! `passless agent mcp playwright` started by an MCP client outside a principal session: the
//! process the client spawned keeps the MCP stdio connection, and the Playwright MCP server, across
//! daemon restarts (ADR 0014 §4.3).
//!
//! ```text
//! MCP client ── stdio ──> wrapper (this process, the client's child)
//!                           ├── Playwright MCP server (its child; inherits the stdio)
//!                           │     └── GET /json/version (bearer) ──> discovery bootstrap (in the wrapper)
//!                           └── broker link (socketpair) ──> `passless agent mcp-session-broker`
//!                                 a principal session the daemon launched; it alone holds fd 3
//! ```
//!
//! Before, the daemon ran the Playwright MCP server inside the principal session with the client's
//! stdio, and the wrapper only waited for the session over the admin socket. Stopping the daemon
//! ended the session tree that held the client's stdio (the principal is bound to the daemon by
//! `PR_SET_PDEATHSIG`, the daemon's shutdown terminates its sessions, and systemd stops the
//! unit's whole cgroup), and the wrapper exited 1 on the admin socket's EOF: the MCP connection
//! was gone, and a client that does not restart MCP servers (opencode) lost the tools.
//!
//! Principal binding is unchanged:
//! - every principal session, the first one and each re-established one, is launched with the same
//!   admin request as `agent run` (`LaunchPrincipal`): the peer checks, the profile's
//!   authorization and limits and the same-user / distinct-UID rules are the daemon's, and grants
//!   and policy come from whichever daemon launches it;
//! - the capability descriptor never leaves the broker, and the wrapper holds no daemon-issued
//!   capability or bearer: it never sees fd 3 and never caches an endpoint, each discovery asks
//!   the current broker. The bootstrap bearer is the wrapper's own, given only to its child;
//! - the broker answers one request, "ensure the browser" (with `direct_cdp`), and exits on its
//!   stdin's EOF, after a sign that its session is no longer valid, or when its parent (the
//!   daemon) is gone;
//! - why a session ended comes from the daemon that ended it (`AdminRequest::SessionEnd`, a
//!   reason it records before it stops the session's process), never from timing. A session it
//!   revoked, terminated or ended with its profile is not re-established: the wrapper exits, as
//!   it did before; so does one it cannot explain (an older daemon, after the grace period).
//!   Re-established, lazily on the next browser tool call: a session lost with its daemon
//!   instance (the daemon is gone, or another daemon process answers), an expired one (once per
//!   expiry, and not a renewal that expired before its first use), and one the wrapper revoked
//!   itself (its broker did not answer in time, or broke the protocol);
//! - the broker also answers one more request since protocol 2, "request access" (ADR 0014
//!   amendment section 2.3), which it maps one to one to `PrincipalRequest::RequestAccess` on its
//!   own session. The session owns the browser, so a `register` approval binds to the right
//!   ceremonies. The wrapper sends it only for the opt-in `--with-access-tool` relay
//!   ([`super::mcp_relay`]), which is otherwise absent: without the flag the Playwright MCP server
//!   inherits the client's stdio and the broker never sees that request;
//! - this applies only when the session runs as the wrapper's own Unix user. A profile whose
//!   sessions run as another user needs the MCP server to run as that user, inside the session, so
//!   the wrapper falls back to the in-session server, which does not survive a restart.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use passless_core::agent::protocol::{
    AccessRequestStatus, AdminRequest, AdminResponse, ErrorCode, GrantAction, ProtocolError,
    RecommendedAction,
};
use passless_core::agent::{
    PrincipalRequest, PrincipalResponse, PrincipalSessionId, ProfileId, SessionEndReason,
};
use passless_core::{Error, Result};

use serde::{Deserialize, Serialize};

use crate::agent::cdp_bootstrap::{CdpBootstrap, EnsureError};
use crate::agent::client::{
    AdminClient, ClientError, DaemonInstance, PrincipalClient, resolve_runtime_base,
};

use super::mcp_relay::{AccessCall, AccessTool, ToolResult};

/// The hidden subcommand the wrapper launches as its principal session.
const BROKER_SUBCOMMAND: &str = "mcp-session-broker";
/// The broker protocol (one JSON object per line). A broker of another version is refused.
/// Version 2 adds `RequestAccess`.
const BROKER_PROTOCOL: u32 = 2;
/// Bounds on admin requests: a launch, and the cheap ones (probe, revoke).
const ADMIN_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a new broker may take to say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(15);
/// How long one "ensure the browser" may take: a launch waits up to 30 s for the extension.
const ENSURE_TIMEOUT: Duration = Duration::from_secs(90);
/// What a "request access" may take beyond its own `wait_ms`: the daemon answers within it, so
/// this only bounds a broker that stopped answering.
const ACCESS_MARGIN: Duration = Duration::from_secs(30);
/// How long a session lost while its daemon still answers may stay undecided: a daemon that is
/// shutting down stops answering within this time; one that keeps answering ended the session.
const LOST_GRACE: Duration = Duration::from_secs(10);
/// How often the wrapper checks its session, and the broker its parent.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// How long the Playwright MCP server gets to exit after SIGTERM.
const STOP_GRACE: Duration = Duration::from_secs(5);
/// The longest line either side accepts.
const MAX_LINE: u64 = 64 * 1024;

/// What the wrapper asks the broker.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum BrokerRequest {
    Ensure,
    /// Protocol 2: `PrincipalRequest::RequestAccess` on the broker's own session.
    RequestAccess {
        rp_id: String,
        action: GrantAction,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wait_ms: Option<u64>,
    },
}

/// What the broker says, one line each.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BrokerMessage {
    /// The first line: the protocol and the Unix user the session runs as.
    Hello { protocol: u32, uid: u32, gid: u32 },
    /// The managed browser's CDP websocket endpoint.
    Ensured { endpoint: String },
    /// The daemon's answer to a `RequestAccess` (every state is a normal answer).
    AccessRequest { status: AccessRequestStatus },
    /// The daemon refused or failed. `session_gone`: the session itself is no longer valid, and
    /// the broker exits after saying so.
    Failed { message: String, session_gone: bool },
}

// ---------------------------------------------------------------------------------------------
// The broker: `passless agent mcp-session-broker`, inside the principal session.
// ---------------------------------------------------------------------------------------------

/// `passless agent mcp-session-broker --profile P [--url U]`.
pub fn serve_broker(profile: &str, url: Option<&str>) -> Result<()> {
    let base = resolve_runtime_base().map_err(client_error)?;
    match PrincipalClient::connect_launched(&base, profile) {
        Ok(_) => {}
        Err(ClientError::NoControlFd) => {
            return Err(Error::Other(format!(
                "`agent {BROKER_SUBCOMMAND}` is internal to `agent mcp playwright` and only runs \
                 in the principal session that command starts"
            )));
        }
        Err(e) => return Err(client_error(e)),
    }
    // SAFETY: `dup` of this process's own stdin; the new descriptor is owned by the stream.
    let input = unsafe {
        let fd = libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3);
        if fd < 0 {
            return Err(Error::Other(format!(
                "cannot read the wrapper's requests: {}",
                std::io::Error::last_os_error()
            )));
        }
        std::fs::File::from_raw_fd(fd)
    };
    let parent = unsafe { libc::getppid() };
    let identity = own_ids();
    serve(
        input,
        &mut std::io::stdout().lock(),
        identity,
        &|| unsafe { libc::getppid() } == parent,
        &mut |request| match request {
            BrokerRequest::Ensure => broker_ensure(profile, url),
            BrokerRequest::RequestAccess {
                rp_id,
                action,
                note,
                wait_ms,
            } => broker_request_access(profile, rp_id, action, note, wait_ms),
        },
    )
}

/// The broker's loop: hello, then one answer per request, until the wrapper closes the link (`Ok`)
/// or the session or its daemon is gone (`Err`).
fn serve<R: Read + AsRawFd, W: Write>(
    input: R,
    output: &mut W,
    (uid, gid): (u32, u32),
    parented: &dyn Fn() -> bool,
    handle: &mut dyn FnMut(BrokerRequest) -> BrokerMessage,
) -> Result<()> {
    let io_error = |e: std::io::Error| Error::Other(format!("broker link: {e}"));
    write_message(
        output,
        &BrokerMessage::Hello {
            protocol: BROKER_PROTOCOL,
            uid,
            gid,
        },
    )
    .map_err(io_error)?;
    let fd = input.as_raw_fd();
    let mut reader = BufReader::new(input);
    loop {
        if reader.buffer().is_empty() && !readable(fd, POLL_INTERVAL) {
            if !parented() {
                return Err(Error::Other(
                    "the daemon that launched this principal session is gone".to_string(),
                ));
            }
            continue;
        }
        let Some(line) = read_line(&mut reader).map_err(io_error)? else {
            return Ok(());
        };
        let request: BrokerRequest = serde_json::from_slice(&line)
            .map_err(|e| Error::Other(format!("broker link: malformed request: {e}")))?;
        let reply = handle(request);
        let gone = matches!(
            reply,
            BrokerMessage::Failed {
                session_gone: true,
                ..
            }
        );
        write_message(output, &reply).map_err(io_error)?;
        if gone {
            return Err(Error::Other(
                "the principal session is no longer valid".to_string(),
            ));
        }
    }
}

/// `EnsureBrowser` for an endpoint (`direct_cdp`: a pipe-mode profile refuses it before anything
/// starts), over this session's capability.
fn broker_ensure(profile: &str, url: Option<&str>) -> BrokerMessage {
    let result = resolve_runtime_base()
        .and_then(|base| PrincipalClient::connect_launched(&base, profile))
        .and_then(|mut client| {
            client.request(PrincipalRequest::EnsureBrowser {
                start_url: url.map(ToOwned::to_owned),
                headed: false,
                direct_cdp: true,
            })
        });
    match result {
        Ok(PrincipalResponse::BrowserEnsured(status)) => match status.cdp_endpoint {
            Some(endpoint) => BrokerMessage::Ensured { endpoint },
            None => BrokerMessage::Failed {
                message: "agent ensured a browser but returned no CDP endpoint".to_string(),
                session_gone: false,
            },
        },
        Ok(_) => BrokerMessage::Failed {
            message: "agent returned an unexpected EnsureBrowser response".to_string(),
            session_gone: false,
        },
        Err(e) => BrokerMessage::Failed {
            session_gone: session_gone(&e),
            message: e.to_string(),
        },
    }
}

/// `RequestAccess` over this session's capability (ADR 0014 amendment section 2.3): the session
/// that owns the browser asks, so a `register` approval binds to this browser's ceremonies. The
/// daemon answers within `wait_ms`; every state is an answer, a refusal of the request itself
/// (malformed, unauthorized) a `Failed`.
fn broker_request_access(
    profile: &str,
    rp_id: String,
    action: GrantAction,
    note: Option<String>,
    wait_ms: Option<u64>,
) -> BrokerMessage {
    let result = resolve_runtime_base()
        .and_then(|base| PrincipalClient::connect_launched(&base, profile))
        .and_then(|mut client| {
            client.request(PrincipalRequest::RequestAccess {
                rp_id,
                action,
                note,
                wait_ms,
            })
        });
    match result {
        Ok(PrincipalResponse::AccessRequest(status)) => BrokerMessage::AccessRequest { status },
        Ok(_) => BrokerMessage::Failed {
            message: "agent returned an unexpected RequestAccess response".to_string(),
            session_gone: false,
        },
        Err(e) => BrokerMessage::Failed {
            session_gone: session_gone(&e),
            message: e.to_string(),
        },
    }
}

/// Whether a failed principal request means that this session no longer exists for the daemon:
/// it is not running, the socket broke, or the capability is not (or no longer) accepted.
fn session_gone(error: &ClientError) -> bool {
    match error {
        ClientError::DaemonNotRunning { .. }
        | ClientError::Io(_)
        | ClientError::Codec(_)
        | ClientError::NoControlFd
        | ClientError::MissingCapability { .. } => true,
        ClientError::Protocol(e) => e.code == ErrorCode::Unauthorized,
        _ => false,
    }
}

// ---------------------------------------------------------------------------------------------
// The wrapper's view of its session: a small state machine over a daemon and a broker link.
// ---------------------------------------------------------------------------------------------

/// A launched session: the link to its broker, the daemon instance that launched it, its id.
pub(crate) struct Launched<L, S> {
    link: L,
    instance: Option<DaemonInstance>,
    session: S,
}

#[derive(Debug, PartialEq)]
pub(crate) enum LaunchError {
    /// Nothing answers on the admin socket (or it does not answer in time).
    Unreachable(String),
    /// The daemon answered and refused, or the session did not start. `fatal`: the daemon
    /// refused the profile itself (unknown or disabled), which no retry changes.
    Refused { message: String, fatal: bool },
    /// The profile's sessions run as another Unix user.
    ForeignUser { uid: u32, gid: u32 },
}

/// The daemon as the admin socket shows it now.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Probe {
    /// Nothing listens: the daemon that was there is gone.
    Down,
    /// A connection, but no answer in time (a daemon that is shutting down, or busy).
    Silent,
    /// A daemon answers; which process, if the kernel says.
    Answering(Option<DaemonInstance>),
}

/// What the daemon says about a session (`AdminRequest::SessionEnd`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum SessionEnd {
    Running,
    /// It ended, for this recorded reason.
    Ended(SessionEndReason),
    /// The daemon cannot say: it predates the request, or no longer knows the session.
    Unknown,
}

/// Why the link to a broker is unusable.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum LinkLost {
    /// The broker closed it: the session process is gone.
    Closed,
    /// No answer in time, or not one the protocol allows: the broker may still run.
    Broken,
}

/// An answer of a live broker.
#[derive(Debug, PartialEq)]
pub(crate) enum BrokerReply {
    Endpoint(String),
    /// The daemon's answer to a request for access.
    Access(AccessRequestStatus),
    /// The daemon refused or failed; the session is fine.
    Refused(String),
    /// The session is no longer valid (the broker exits).
    SessionGone(String),
}

pub(crate) trait Daemon {
    type Link: Link;
    type Session;
    fn launch(&mut self) -> std::result::Result<Launched<Self::Link, Self::Session>, LaunchError>;
    fn probe(&mut self) -> Probe;
    /// Why the daemon ended a session (asked of the daemon that launched it).
    fn session_end(&mut self, session: &Self::Session) -> SessionEnd;
    /// Revoke a session; `true` when this revocation ended it (the daemon still had it).
    fn revoke(&mut self, session: &Self::Session) -> bool;
}

pub(crate) trait Link {
    fn ensure(&mut self) -> std::result::Result<BrokerReply, LinkLost>;
    /// Ask the broker's session for access (`RequestAccess`); may wait for the human.
    fn request_access(&mut self, call: &AccessCall) -> std::result::Result<BrokerReply, LinkLost>;
    /// Without blocking: whether the broker went away (`Closed`) or spoke unasked (`Broken`)
    /// since the last request.
    fn lost(&mut self) -> Option<LinkLost>;
}

/// How the current session came to be, for the renewal limit.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Origin {
    /// Launched to replace an expired session.
    renewal: bool,
    /// It handed out an endpoint at least once.
    served: bool,
}

enum State<L, S> {
    Live {
        link: L,
        instance: Option<DaemonInstance>,
        session: S,
        origin: Origin,
    },
    /// The session is gone; `instance` launched it.
    Lost {
        instance: Option<DaemonInstance>,
        session: S,
        origin: Origin,
        since: Instant,
    },
    /// No session, and launching one is allowed: the next browser request does. `renewal`: the
    /// one it replaces expired.
    Idle { renewal: bool },
    /// No new session, for the reason given: the wrapper exits.
    Ended(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Health {
    Running,
    /// The live daemon ended the session for good; the wrapper exits with this message.
    Ended(String),
}

enum Resolution {
    /// The daemon is down: the next request launches when it is back.
    Down,
    /// Another daemon instance answers, or the session expired: launch now.
    Relaunch,
    /// Not decided yet (no answer, or the end not recorded yet).
    Pending,
    /// No new session.
    Ended,
}

/// The wrapper's principal session: launched at start, re-established after its daemon went
/// away or after it expired, never after the live daemon ended it on purpose.
pub(crate) struct SessionKeeper<D: Daemon> {
    daemon: D,
    state: State<D::Link, D::Session>,
    grace: Duration,
}

impl<D: Daemon> SessionKeeper<D> {
    /// Launch the first session; failing that, the wrapper does not start.
    pub(crate) fn start(mut daemon: D, grace: Duration) -> std::result::Result<Self, LaunchError> {
        let launched = daemon.launch()?;
        Ok(Self {
            daemon,
            state: live(launched, false),
            grace,
        })
    }

    /// The managed browser's endpoint, from the current session's broker, after re-establishing
    /// the session if its daemon went away or it expired. At most one launch per call, and never
    /// blocks beyond the admin and link timeouts.
    pub(crate) fn ensure(&mut self) -> std::result::Result<String, EnsureError> {
        match self.dispatch(&mut |link| link.ensure())? {
            BrokerReply::Endpoint(endpoint) => Ok(endpoint),
            _ => Err(unexpected_reply()),
        }
    }

    /// Ask the current session's daemon for access (`RequestAccess`), after re-establishing the
    /// session like [`Self::ensure`] does. Blocks for the human's decision, up to the call's
    /// `wait_ms` plus [`ACCESS_MARGIN`]; the keeper is held meanwhile, so the wrapper's other
    /// requests to its broker queue behind it.
    pub(crate) fn request_access(
        &mut self,
        call: &AccessCall,
    ) -> std::result::Result<AccessRequestStatus, EnsureError> {
        match self.dispatch(&mut |link| link.request_access(call))? {
            BrokerReply::Access(status) => Ok(status),
            _ => Err(unexpected_reply()),
        }
    }

    /// Run `request` on the current session's link; a lost link is resolved (and the session
    /// re-established when the daemon's answers say so) exactly as for an ensure.
    fn dispatch(
        &mut self,
        request: &mut dyn FnMut(&mut D::Link) -> std::result::Result<BrokerReply, LinkLost>,
    ) -> std::result::Result<BrokerReply, EnsureError> {
        let mut launched = false;
        // Enough for: a lost link, its resolution, a launch, the request on the new link and,
        // if that one is lost too, its resolution (the single launch bounds the rest).
        for _ in 0..6 {
            match std::mem::replace(&mut self.state, State::Idle { renewal: false }) {
                State::Live {
                    mut link,
                    instance,
                    session,
                    mut origin,
                } => match request(&mut link) {
                    Ok(reply @ (BrokerReply::Endpoint(_) | BrokerReply::Access(_))) => {
                        if matches!(reply, BrokerReply::Endpoint(_)) {
                            origin.served = true;
                        }
                        self.state = State::Live {
                            link,
                            instance,
                            session,
                            origin,
                        };
                        return Ok(reply);
                    }
                    Ok(BrokerReply::Refused(message)) => {
                        self.state = State::Live {
                            link,
                            instance,
                            session,
                            origin,
                        };
                        return Err(EnsureError::from(message));
                    }
                    Ok(BrokerReply::SessionGone(_)) | Err(LinkLost::Closed) => {
                        self.lose(link, instance, session, origin, false);
                    }
                    Err(LinkLost::Broken) => self.lose(link, instance, session, origin, true),
                },
                lost @ State::Lost { .. } => {
                    self.state = lost;
                    match self.resolve() {
                        Resolution::Relaunch => {}
                        Resolution::Down => return Err(unavailable("it does not answer")),
                        Resolution::Pending => return Err(session_lost()),
                        Resolution::Ended => return Err(self.ended_error()),
                    }
                }
                State::Idle { renewal } if launched => {
                    // A session launched by this very call is gone already: stop here rather
                    // than launch another; the next call decides.
                    self.state = State::Idle { renewal };
                    return Err(session_lost());
                }
                State::Idle { renewal } => {
                    launched = true;
                    match self.daemon.launch() {
                        Ok(new) => self.state = live(new, renewal),
                        Err(LaunchError::Unreachable(detail)) => {
                            self.state = State::Idle { renewal };
                            return Err(unavailable(&detail));
                        }
                        Err(LaunchError::Refused {
                            message,
                            fatal: false,
                        }) => {
                            self.state = State::Idle { renewal };
                            return Err(EnsureError::from(message));
                        }
                        Err(LaunchError::Refused {
                            message,
                            fatal: true,
                        }) => {
                            self.state = State::Ended(format!(
                                "the daemon refuses this MCP server's profile ({message}); it \
                                 is not re-established"
                            ));
                            return Err(self.ended_error());
                        }
                        Err(LaunchError::ForeignUser { uid, gid }) => {
                            // The profile changed under a running wrapper: its server would
                            // have to run as that user now.
                            self.state = State::Ended(format!(
                                "the profile's principal sessions now run as uid {uid} gid \
                                 {gid}, not as this MCP server's user; restart the MCP server"
                            ));
                            return Err(self.ended_error());
                        }
                    }
                }
                ended @ State::Ended(_) => {
                    self.state = ended;
                    return Err(self.ended_error());
                }
            }
        }
        Err(unavailable("the session could not be re-established"))
    }

    /// Notice a lost session between requests (the wrapper polls this), and tell whether the
    /// live daemon ended it for good.
    pub(crate) fn poll(&mut self) -> Health {
        if let State::Live { link, .. } = &mut self.state
            && let Some(how) = link.lost()
            && let State::Live {
                link,
                instance,
                session,
                origin,
            } = std::mem::replace(&mut self.state, State::Idle { renewal: false })
        {
            // Data nobody asked for is a protocol violation: that broker may still run.
            self.lose(link, instance, session, origin, how == LinkLost::Broken);
        }
        if matches!(self.state, State::Lost { .. }) {
            self.resolve();
        }
        match &self.state {
            State::Ended(message) => Health::Ended(message.clone()),
            _ => Health::Running,
        }
    }

    /// Close the link (the broker exits on its EOF), revoking the session too when asked.
    pub(crate) fn shutdown(&mut self, revoke: bool) {
        let ended = State::Ended("this MCP server is stopping".to_string());
        if let State::Live { link, session, .. } = std::mem::replace(&mut self.state, ended) {
            drop(link);
            if revoke {
                let _ = self.daemon.revoke(&session);
            }
        }
    }

    /// Drop a link that is no longer usable. A broker that may still run (`revoke`) is revoked
    /// (closing the link also makes it exit): when that revocation is what ended the session,
    /// the wrapper ended it, and a new one may be launched. Otherwise (the broker closed the
    /// link, or the daemon no longer had the session) the session is lost, and
    /// [`Self::resolve`] asks the daemon why.
    fn lose(
        &mut self,
        link: D::Link,
        instance: Option<DaemonInstance>,
        session: D::Session,
        origin: Origin,
        revoke: bool,
    ) {
        drop(link);
        if revoke && self.daemon.revoke(&session) {
            self.state = State::Idle { renewal: false };
            return;
        }
        self.state = State::Lost {
            instance,
            session,
            origin,
            since: Instant::now(),
        };
    }

    /// Decide what a lost session means from what the daemon says, never from timing alone:
    /// - its daemon is gone, or another daemon process answers: launch a new one;
    /// - the daemon that launched it says it expired: renew it, once per expiry, and not when a
    ///   renewed session expired before it handed out a single endpoint (a `max_session_ttl`
    ///   too short to use: renewing it would only loop);
    /// - it says the session was revoked, terminated, its profile disabled, or it exited: end;
    /// - it says nothing yet (still running, no answer): wait;
    /// - it cannot say (a daemon without `SessionEnd`, a forgotten session): as before reasons
    ///   existed, wait for the grace period, then end. An unknown reason never renews.
    fn resolve(&mut self) -> Resolution {
        let State::Lost {
            instance,
            ref session,
            origin,
            since,
        } = self.state
        else {
            return Resolution::Pending;
        };
        let (resolution, renewal, message) = match self.daemon.probe() {
            Probe::Down => (Resolution::Down, false, None),
            Probe::Answering(Some(now)) if instance != Some(now) => {
                (Resolution::Relaunch, false, None)
            }
            Probe::Silent => (Resolution::Pending, false, None),
            Probe::Answering(_) => match self.daemon.session_end(session) {
                SessionEnd::Ended(SessionEndReason::Expired)
                    if origin.renewal && !origin.served =>
                {
                    (
                        Resolution::Ended,
                        false,
                        Some(
                            "its renewed principal session expired before it was used \
                             (max_session_ttl is too short to use); not renewing it again"
                                .to_string(),
                        ),
                    )
                }
                SessionEnd::Ended(SessionEndReason::Expired) => (Resolution::Relaunch, true, None),
                SessionEnd::Ended(reason) => (
                    Resolution::Ended,
                    false,
                    Some(format!(
                        "the daemon ended this MCP server's principal session ({}); it is not \
                         re-established",
                        describe(reason)
                    )),
                ),
                SessionEnd::Running => (Resolution::Pending, false, None),
                SessionEnd::Unknown if since.elapsed() >= self.grace => (
                    Resolution::Ended,
                    false,
                    Some(
                        "the daemon ended this MCP server's principal session and does not say \
                         why; it is not re-established"
                            .to_string(),
                    ),
                ),
                SessionEnd::Unknown => (Resolution::Pending, false, None),
            },
        };
        match resolution {
            Resolution::Down | Resolution::Relaunch => self.state = State::Idle { renewal },
            Resolution::Ended => {
                self.state = State::Ended(message.unwrap_or_else(|| session_ended().message));
            }
            Resolution::Pending => {}
        }
        resolution
    }

    fn ended_error(&self) -> EnsureError {
        match &self.state {
            State::Ended(message) => EnsureError::new("session_ended", message.clone()),
            _ => session_ended(),
        }
    }

    #[cfg(test)]
    fn state_name(&self) -> &'static str {
        match self.state {
            State::Live { .. } => "live",
            State::Lost { .. } => "lost",
            State::Idle { .. } => "idle",
            State::Ended(_) => "ended",
        }
    }
}

fn live<L, S>(launched: Launched<L, S>, renewal: bool) -> State<L, S> {
    State::Live {
        link: launched.link,
        instance: launched.instance,
        session: launched.session,
        origin: Origin {
            renewal,
            served: false,
        },
    }
}

/// A recorded end reason, as the wrapper's message says it.
fn describe(reason: SessionEndReason) -> &'static str {
    match reason {
        SessionEndReason::Expired => "expired",
        SessionEndReason::Revoked => "revoked",
        SessionEndReason::Terminated => "terminated",
        SessionEndReason::ProfileDisabled => "its profile was disabled",
        SessionEndReason::Exited => "its process exited",
        SessionEndReason::ClientGone => "its client is gone",
        SessionEndReason::DaemonShutdown => "the daemon shut down",
        SessionEndReason::Unknown => "for a reason this passless does not know",
    }
}

fn unexpected_reply() -> EnsureError {
    EnsureError::new(
        "protocol",
        "the broker answered a request with a reply of another kind",
    )
}

fn unavailable(detail: &str) -> EnsureError {
    EnsureError::new(
        "daemon_unreachable",
        format!("passless daemon unavailable, retrying on the next browser tool call: {detail}"),
    )
}

fn session_lost() -> EnsureError {
    EnsureError::new(
        "session_lost",
        "the principal session ended and the daemon has not said why yet; retry in a moment",
    )
}

fn session_ended() -> EnsureError {
    EnsureError::new(
        "session_ended",
        "the daemon ended this MCP server's principal session (revoked, its profile disabled or \
         removed); it is not re-established",
    )
}

// ---------------------------------------------------------------------------------------------
// The real daemon (the admin socket) and broker link (a socketpair).
// ---------------------------------------------------------------------------------------------

pub(crate) struct AdminDaemon {
    profile: ProfileId,
    argv: Vec<String>,
    /// The agent runtime directory; `None` resolves it on every call, as every client does.
    base: Option<PathBuf>,
}

impl AdminDaemon {
    fn connect(&self, timeout: Duration) -> std::result::Result<AdminClient, ClientError> {
        let base = match &self.base {
            Some(base) => base.clone(),
            None => resolve_runtime_base()?,
        };
        let client = AdminClient::connect(&base)?;
        client.set_timeout(timeout)?;
        Ok(client)
    }
}

impl Daemon for AdminDaemon {
    type Link = BrokerLink;
    type Session = PrincipalSessionId;

    fn launch(
        &mut self,
    ) -> std::result::Result<Launched<BrokerLink, PrincipalSessionId>, LaunchError> {
        let mut client = self
            .connect(ADMIN_TIMEOUT)
            .map_err(|e| LaunchError::Unreachable(e.to_string()))?;
        let instance = client.daemon_instance();
        let (ours, theirs) = UnixStream::pair().map_err(|e| LaunchError::Refused {
            message: format!("cannot create the broker link: {e}"),
            fatal: false,
        })?;
        let response = client.launch_principal_with_stdio(
            &self.profile,
            self.argv.clone(),
            theirs.as_raw_fd(),
            theirs.as_raw_fd(),
            libc::STDERR_FILENO,
        );
        // Only the broker holds the other end now: its exit is this link's EOF.
        drop(theirs);
        let session = match response {
            Ok(AdminResponse::PrincipalLaunched(launched)) => launched.session_id,
            Ok(_) => {
                return Err(LaunchError::Refused {
                    message: "the daemon answered the session launch with an unexpected response"
                        .into(),
                    fatal: false,
                });
            }
            Err(ClientError::Protocol(e)) => {
                // An unknown or disabled profile (or an executable the daemon will not run)
                // stays refused; a full session limit may not.
                let fatal = matches!(e.code, ErrorCode::NotFound | ErrorCode::Forbidden);
                return Err(LaunchError::Refused {
                    message: format!("the daemon refused the principal session: {e}"),
                    fatal,
                });
            }
            Err(e) => return Err(LaunchError::Unreachable(e.to_string())),
        };
        let link = BrokerLink::new(ours, ENSURE_TIMEOUT);
        let hello = link
            .map_err(|_| LinkLost::Broken)
            .and_then(|mut link| link.hello(HELLO_TIMEOUT).map(|hello| (link, hello)));
        match hello {
            Ok((link, hello)) => match check_hello(hello, own_ids()) {
                Ok(()) => Ok(Launched {
                    link,
                    instance,
                    session,
                }),
                Err(refusal) => {
                    drop(link);
                    let _ = self.revoke(&session);
                    Err(refusal)
                }
            },
            Err(_) => {
                let _ = self.revoke(&session);
                Err(LaunchError::Refused {
                    message: "the principal session started but its broker did not answer"
                        .to_string(),
                    fatal: false,
                })
            }
        }
    }

    fn session_end(&mut self, session: &PrincipalSessionId) -> SessionEnd {
        let Ok(mut client) = self.connect(PROBE_TIMEOUT) else {
            return SessionEnd::Unknown;
        };
        // A daemon that predates `SessionEnd` refuses it (malformed): the reason is unknown.
        match client.request(AdminRequest::SessionEnd {
            session_id: session.clone(),
        }) {
            Ok(AdminResponse::SessionEnd(end)) if end.running => SessionEnd::Running,
            Ok(AdminResponse::SessionEnd(end)) => {
                SessionEnd::Ended(end.reason.unwrap_or(SessionEndReason::Unknown))
            }
            _ => SessionEnd::Unknown,
        }
    }

    fn probe(&mut self) -> Probe {
        let Ok(mut client) = self.connect(PROBE_TIMEOUT) else {
            return Probe::Down;
        };
        match client.request(AdminRequest::Ping) {
            Ok(AdminResponse::Pong) => Probe::Answering(client.daemon_instance()),
            _ => Probe::Silent,
        }
    }

    fn revoke(&mut self, session: &PrincipalSessionId) -> bool {
        let Ok(mut client) = self.connect(PROBE_TIMEOUT) else {
            return false;
        };
        matches!(
            client.request(AdminRequest::RevokeSession {
                session_id: session.clone(),
            }),
            Ok(AdminResponse::SessionRevoked)
        )
    }
}

/// The wrapper's end of the link to a broker.
pub(crate) struct BrokerLink {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
    ensure_timeout: Duration,
}

impl BrokerLink {
    fn new(stream: UnixStream, ensure_timeout: Duration) -> std::io::Result<Self> {
        Ok(Self {
            reader: BufReader::new(stream.try_clone()?),
            writer: stream,
            ensure_timeout,
        })
    }

    fn receive(&mut self, timeout: Duration) -> std::result::Result<BrokerMessage, LinkLost> {
        self.reader
            .get_ref()
            .set_read_timeout(Some(timeout))
            .map_err(|_| LinkLost::Broken)?;
        match read_line(&mut self.reader) {
            Ok(Some(line)) => serde_json::from_slice(&line).map_err(|_| LinkLost::Broken),
            Ok(None) => Err(LinkLost::Closed),
            Err(e) => Err(lost_by(&e)),
        }
    }

    /// The broker's first line: (protocol, uid, gid).
    fn hello(&mut self, timeout: Duration) -> std::result::Result<(u32, u32, u32), LinkLost> {
        match self.receive(timeout)? {
            BrokerMessage::Hello { protocol, uid, gid } => Ok((protocol, uid, gid)),
            _ => Err(LinkLost::Broken),
        }
    }
}

impl BrokerLink {
    /// Send one request line and read the broker's one answer line within `timeout`.
    fn exchange(
        &mut self,
        request: &BrokerRequest,
        timeout: Duration,
    ) -> std::result::Result<BrokerMessage, LinkLost> {
        let mut line = serde_json::to_vec(request).map_err(|_| LinkLost::Broken)?;
        line.push(b'\n');
        self.writer.write_all(&line).map_err(|e| lost_by(&e))?;
        self.receive(timeout)
    }
}

impl Link for BrokerLink {
    fn ensure(&mut self) -> std::result::Result<BrokerReply, LinkLost> {
        match self.exchange(&BrokerRequest::Ensure, self.ensure_timeout)? {
            BrokerMessage::Ensured { endpoint } => Ok(BrokerReply::Endpoint(endpoint)),
            BrokerMessage::Failed {
                message,
                session_gone: true,
            } => Ok(BrokerReply::SessionGone(message)),
            BrokerMessage::Failed { message, .. } => Ok(BrokerReply::Refused(message)),
            // An answer of the other kind, or a second hello, is not the protocol.
            BrokerMessage::Hello { .. } | BrokerMessage::AccessRequest { .. } => {
                Err(LinkLost::Broken)
            }
        }
    }

    fn request_access(&mut self, call: &AccessCall) -> std::result::Result<BrokerReply, LinkLost> {
        let request = BrokerRequest::RequestAccess {
            rp_id: call.rp_id.clone(),
            action: call.action.clone(),
            note: call.note.clone(),
            wait_ms: Some(call.wait_ms),
        };
        let timeout = Duration::from_millis(call.wait_ms) + ACCESS_MARGIN;
        match self.exchange(&request, timeout)? {
            BrokerMessage::AccessRequest { status } => Ok(BrokerReply::Access(status)),
            BrokerMessage::Failed {
                message,
                session_gone: true,
            } => Ok(BrokerReply::SessionGone(message)),
            BrokerMessage::Failed { message, .. } => Ok(BrokerReply::Refused(message)),
            BrokerMessage::Hello { .. } | BrokerMessage::Ensured { .. } => Err(LinkLost::Broken),
        }
    }

    fn lost(&mut self) -> Option<LinkLost> {
        // Between requests the broker says nothing: EOF or an error means it is gone, data means
        // it broke the protocol.
        if !self.reader.buffer().is_empty() {
            return Some(LinkLost::Broken);
        }
        let fd = self.reader.get_ref().as_raw_fd();
        if !readable(fd, Duration::ZERO) {
            return None;
        }
        let mut byte = 0u8;
        // SAFETY: a one-byte peek into a valid buffer; nothing is consumed.
        let peeked = unsafe {
            libc::recv(
                fd,
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        match peeked {
            1.. => Some(LinkLost::Broken),
            0 => Some(LinkLost::Closed),
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock => None,
            _ => Some(LinkLost::Closed),
        }
    }
}

/// Whether a broker's hello (protocol, uid, gid) is one this wrapper can use: its own protocol,
/// and the wrapper's own Unix user. A broker of another protocol (passless was upgraded under a
/// running MCP server, in either direction) is refused for good: restarting the MCP server is the
/// fix.
fn check_hello(
    (protocol, uid, gid): (u32, u32, u32),
    own: (u32, u32),
) -> std::result::Result<(), LaunchError> {
    if protocol != BROKER_PROTOCOL {
        return Err(LaunchError::Refused {
            message: format!(
                "the principal session speaks broker protocol {protocol}, this MCP server \
                 {BROKER_PROTOCOL} (passless was upgraded): restart the MCP server"
            ),
            fatal: true,
        });
    }
    if (uid, gid) != own {
        return Err(LaunchError::ForeignUser { uid, gid });
    }
    Ok(())
}

/// A closed socket is a gone broker; anything else (a timeout, bad data) is a broken one.
fn lost_by(error: &std::io::Error) -> LinkLost {
    match error.kind() {
        std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::UnexpectedEof => LinkLost::Closed,
        _ => LinkLost::Broken,
    }
}

// ---------------------------------------------------------------------------------------------
// The wrapper.
// ---------------------------------------------------------------------------------------------

/// Run `agent mcp playwright` for an MCP client outside a principal session (see the module
/// documentation). `Ok(None)`: the profile's sessions run as another Unix user; the caller runs the
/// server inside a session instead.
pub(super) fn run_playwright(
    profile: &str,
    url: Option<&str>,
    command: &[PathBuf],
    with_access_tool: bool,
) -> Result<Option<()>> {
    let executable = super::playwright_mcp::check_command(command)?;
    let daemon = AdminDaemon {
        profile: ProfileId::new(profile).map_err(|e| Error::Other(e.to_string()))?,
        argv: broker_argv(&broker_executable()?, profile, url),
        base: None,
    };
    let keeper = match SessionKeeper::start(daemon, LOST_GRACE) {
        Ok(keeper) => keeper,
        Err(LaunchError::ForeignUser { uid, gid }) => {
            eprintln!(
                "passless: profile '{profile}' runs its principal sessions as uid {uid} gid {gid}: \
                 the Playwright MCP server runs inside the session as that user, and does not \
                 survive a daemon restart"
            );
            return Ok(None);
        }
        Err(LaunchError::Unreachable(message) | LaunchError::Refused { message, .. }) => {
            return Err(Error::Other(message));
        }
    };
    let keeper = Arc::new(Mutex::new(keeper));
    let token = super::playwright_mcp::bootstrap_token()?;
    let for_bootstrap = Arc::clone(&keeper);
    let bootstrap = CdpBootstrap::start(token.clone(), move || lock(&for_bootstrap).ensure())
        .map_err(|e| Error::Other(e.to_string()))?;
    let child_command = super::playwright_mcp::server_command(
        profile,
        command,
        &bootstrap.endpoint(),
        &token,
        false,
    );
    // The opt-in relay (`--with-access-tool`): the server's stdio goes through it; without the
    // flag the server inherits the client's.
    let tool: Option<Arc<dyn AccessTool>> = with_access_tool.then(|| {
        Arc::new(KeeperTool {
            keeper: Arc::clone(&keeper),
        }) as Arc<dyn AccessTool>
    });
    let result = supervise(child_command, executable, &keeper, tool);
    drop(bootstrap);
    result.map(Some)
}

/// `passless_request_access` through the wrapper's own principal session (its broker).
struct KeeperTool {
    keeper: Arc<Mutex<SessionKeeper<AdminDaemon>>>,
}

impl AccessTool for KeeperTool {
    fn call(&self, call: AccessCall) -> ToolResult {
        lock(&self.keeper).request_access(&call).map_err(|e| {
            ProtocolError::new(ErrorCode::Internal, e.message, RecommendedAction::Retry)
        })
    }
}

/// This executable, by the path it was started from: after an upgrade replaced the file, a new
/// session runs the new one (`/proc/self/exe` would name the deleted file).
fn broker_executable() -> Result<PathBuf> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::Other(format!("failed to resolve the passless executable: {e}")))?;
    let text = exe.to_string_lossy();
    Ok(match text.strip_suffix(" (deleted)") {
        Some(original) => PathBuf::from(original),
        None => exe,
    })
}

/// The broker's command line: the profile and start URL, nothing secret.
fn broker_argv(executable: &Path, profile: &str, url: Option<&str>) -> Vec<String> {
    let mut argv = vec![
        executable.to_string_lossy().into_owned(),
        "agent".to_string(),
        BROKER_SUBCOMMAND.to_string(),
        "--profile".to_string(),
        profile.to_string(),
    ];
    if let Some(url) = url {
        argv.extend(["--url".to_string(), url.to_string()]);
    }
    argv
}

/// Run the Playwright MCP server until it exits (its status is ours), this process is told to
/// stop or loses its parent, or the live daemon ends the session.
fn supervise<D: Daemon>(
    mut child_command: Command,
    executable: &Path,
    keeper: &Mutex<SessionKeeper<D>>,
    relay: Option<Arc<dyn AccessTool>>,
) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        signal_hook::flag::register(signal, Arc::clone(&stop))
            .map_err(|e| Error::Other(format!("failed to register a signal handler: {e}")))?;
    }
    let parent = unsafe { libc::getppid() };
    let spawned = match relay {
        Some(tool) => super::mcp_relay::spawn_relayed(&mut child_command, tool)
            .map(|(child, handle)| (child, Some(handle))),
        None => child_command.spawn().map(|child| (child, None)),
    };
    let (mut child, relay) = spawned.map_err(|e| {
        Error::Other(format!(
            "failed to start Playwright MCP executable '{}': {e}",
            executable.display()
        ))
    })?;
    let mut last_poll = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                shutdown(keeper, false);
                // The server's last output still reaches the client.
                if let Some(relay) = relay {
                    relay.finish();
                }
                return super::playwright_mcp::exit_result("Playwright MCP", status);
            }
            Ok(None) => {}
            Err(e) => {
                stop_child(&mut child);
                shutdown(keeper, true);
                return Err(Error::Other(format!(
                    "failed waiting for Playwright MCP: {e}"
                )));
            }
        }
        if stop.load(Ordering::SeqCst) || unsafe { libc::getppid() } != parent {
            stop_child(&mut child);
            shutdown(keeper, true);
            return Err(Error::Other("terminated by signal".to_string()));
        }
        if last_poll.elapsed() >= POLL_INTERVAL {
            last_poll = Instant::now();
            // A discovery in progress holds the keeper; it notices a lost session itself.
            let health = match keeper.try_lock() {
                Ok(mut keeper) => keeper.poll(),
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().poll(),
                Err(TryLockError::WouldBlock) => Health::Running,
            };
            if let Health::Ended(message) = health {
                stop_child(&mut child);
                shutdown(keeper, false);
                return Err(Error::Other(format!("{message}; stopped Playwright MCP")));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn shutdown<D: Daemon>(keeper: &Mutex<SessionKeeper<D>>, revoke: bool) {
    // Never wait for a discovery in progress: this process's exit closes the link anyway.
    match keeper.try_lock() {
        Ok(mut keeper) => keeper.shutdown(revoke),
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().shutdown(revoke),
        Err(TryLockError::WouldBlock) => {}
    }
}

/// SIGTERM, then SIGKILL after [`STOP_GRACE`].
fn stop_child(child: &mut Child) {
    // SAFETY: a plain signal to our own, not yet reaped, child.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    let deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------------------------

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn own_ids() -> (u32, u32) {
    // SAFETY: plain getters.
    unsafe { (libc::getuid(), libc::getgid()) }
}

fn client_error(error: ClientError) -> Error {
    Error::Other(error.to_string())
}

/// Whether `fd` has something to read (data, EOF, an error) within `timeout`.
fn readable(fd: RawFd, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    };
    let millis = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    // SAFETY: one valid pollfd.
    unsafe { libc::poll(&mut pfd, 1, millis) > 0 }
}

/// One `\n`-terminated line of at most [`MAX_LINE`] bytes, without the `\n`; `None` at EOF.
fn read_line<R: BufRead>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let read = reader
        .by_ref()
        .take(MAX_LINE)
        .read_until(b'\n', &mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.pop() != Some(b'\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            if read as u64 >= MAX_LINE {
                "line too long"
            } else {
                "truncated line"
            },
        ));
    }
    Ok(Some(line))
}

fn write_message<W: Write>(output: &mut W, message: &BrokerMessage) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(message).map_err(std::io::Error::other)?;
    line.push(b'\n');
    output.write_all(&line)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;

    const A: DaemonInstance = DaemonInstance {
        pid: 100,
        start_time: 1,
    };
    const B: DaemonInstance = DaemonInstance {
        pid: 200,
        start_time: 2,
    };

    /// What every fake link and the fake daemon record.
    #[derive(Default)]
    struct Journal {
        /// `ensure@<session>` per request, in order.
        calls: Vec<String>,
        launched: Vec<u32>,
        revoked: Vec<u32>,
        probes: usize,
    }

    struct FakeLink {
        session: u32,
        journal: Arc<Mutex<Journal>>,
        gone: Arc<AtomicBool>,
        replies: VecDeque<std::result::Result<BrokerReply, LinkLost>>,
    }

    impl Link for FakeLink {
        fn ensure(&mut self) -> std::result::Result<BrokerReply, LinkLost> {
            lock(&self.journal)
                .calls
                .push(format!("ensure@{}", self.session));
            if self.gone.load(Ordering::SeqCst) {
                return Err(LinkLost::Closed);
            }
            self.replies.pop_front().unwrap_or_else(|| {
                Ok(BrokerReply::Endpoint(format!(
                    "ws://127.0.0.1:9/devtools/browser/{}",
                    self.session
                )))
            })
        }

        fn request_access(
            &mut self,
            call: &AccessCall,
        ) -> std::result::Result<BrokerReply, LinkLost> {
            lock(&self.journal)
                .calls
                .push(format!("access@{}:{}", self.session, call.rp_id));
            if self.gone.load(Ordering::SeqCst) {
                return Err(LinkLost::Closed);
            }
            self.replies.pop_front().unwrap_or_else(|| {
                Ok(BrokerReply::Access(AccessRequestStatus {
                    state: passless_core::agent::protocol::AccessRequestState::Approved,
                    rp_id: call.rp_id.clone(),
                    action: call.action.clone(),
                    expires_in_secs: None,
                    retry_after_secs: None,
                    message: format!("approved through session {}", self.session),
                }))
            })
        }

        fn lost(&mut self) -> Option<LinkLost> {
            self.gone.load(Ordering::SeqCst).then_some(LinkLost::Closed)
        }
    }

    /// A daemon whose availability, identity and launches the test controls.
    struct FakeDaemon {
        journal: Arc<Mutex<Journal>>,
        /// `None`: down. `Some(i)`: instance `i` answers.
        up: Option<DaemonInstance>,
        silent: bool,
        foreign: bool,
        /// The daemon already ended the sessions it handed out (a revocation finds nothing).
        forgot: bool,
        /// A launch refusal and whether it is fatal.
        refuse: Option<(String, bool)>,
        /// What `SessionEnd` answers (an old daemon: `Unknown`).
        end: SessionEnd,
        next: u32,
        /// The `gone` switch of every link handed out, by session.
        links: Vec<Arc<AtomicBool>>,
        replies: VecDeque<std::result::Result<BrokerReply, LinkLost>>,
    }

    impl FakeDaemon {
        fn new(journal: &Arc<Mutex<Journal>>) -> Self {
            Self {
                journal: Arc::clone(journal),
                up: Some(A),
                silent: false,
                foreign: false,
                forgot: false,
                refuse: None,
                end: SessionEnd::Unknown,
                next: 1,
                links: Vec::new(),
                replies: VecDeque::new(),
            }
        }
    }

    impl Daemon for FakeDaemon {
        type Link = FakeLink;
        type Session = u32;

        fn launch(&mut self) -> std::result::Result<Launched<FakeLink, u32>, LaunchError> {
            let Some(instance) = self.up.filter(|_| !self.silent) else {
                return Err(LaunchError::Unreachable(
                    "the passless daemon is not running".into(),
                ));
            };
            if let Some((message, fatal)) = &self.refuse {
                return Err(LaunchError::Refused {
                    message: message.clone(),
                    fatal: *fatal,
                });
            }
            if self.foreign {
                return Err(LaunchError::ForeignUser {
                    uid: 4242,
                    gid: 4242,
                });
            }
            let session = self.next;
            self.next += 1;
            lock(&self.journal).launched.push(session);
            let gone = Arc::new(AtomicBool::new(false));
            self.links.push(Arc::clone(&gone));
            Ok(Launched {
                link: FakeLink {
                    session,
                    journal: Arc::clone(&self.journal),
                    gone,
                    replies: std::mem::take(&mut self.replies),
                },
                instance: Some(instance),
                session,
            })
        }

        fn probe(&mut self) -> Probe {
            lock(&self.journal).probes += 1;
            match (self.up, self.silent) {
                (None, _) => Probe::Down,
                (Some(_), true) => Probe::Silent,
                (Some(instance), false) => Probe::Answering(Some(instance)),
            }
        }

        fn session_end(&mut self, _session: &u32) -> SessionEnd {
            self.end
        }

        fn revoke(&mut self, session: &u32) -> bool {
            lock(&self.journal).revoked.push(*session);
            // A live daemon knows its sessions unless it ended them itself.
            self.up.is_some() && !self.silent && !self.forgot
        }
    }

    fn keeper(grace: Duration) -> (SessionKeeper<FakeDaemon>, Arc<Mutex<Journal>>) {
        let journal = Arc::new(Mutex::new(Journal::default()));
        let keeper = SessionKeeper::start(FakeDaemon::new(&journal), grace)
            .unwrap_or_else(|_| panic!("the first launch succeeds"));
        (keeper, journal)
    }

    /// The broker of `session` exits (its daemon went away with it).
    fn broker_exits(keeper: &SessionKeeper<FakeDaemon>, session: u32) {
        keeper.daemon.links[session as usize - 1].store(true, Ordering::SeqCst);
    }

    fn calls_to(journal: &Arc<Mutex<Journal>>, session: u32) -> usize {
        let tag = format!("ensure@{session}");
        lock(journal).calls.iter().filter(|c| **c == tag).count()
    }

    /// Present, gone, back: the wrapper keeps running, fails fast and clearly while the daemon is
    /// down, and the next request after it is back launches a new session through the daemon and
    /// never touches the old one.
    #[test]
    fn the_session_is_re_established_after_its_daemon_restarts() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        assert_eq!(
            keeper.ensure().unwrap(),
            "ws://127.0.0.1:9/devtools/browser/1"
        );
        assert_eq!(keeper.state_name(), "live");

        // The daemon stops: its session's broker exits with it.
        keeper.daemon.up = None;
        broker_exits(&keeper, 1);
        assert_eq!(keeper.poll(), Health::Running, "the wrapper keeps running");
        assert_eq!(
            keeper.state_name(),
            "idle",
            "a gone daemon allows a new session"
        );
        let calls_before = calls_to(&journal, 1);

        for _ in 0..3 {
            let started = Instant::now();
            let err = keeper.ensure().unwrap_err();
            assert!(started.elapsed() < Duration::from_secs(1), "fails fast");
            assert_eq!(err.class, Some("daemon_unreachable"), "{err:?}");
            assert!(
                err.message
                    .contains("passless daemon unavailable, retrying"),
                "{err:?}"
            );
        }
        assert_eq!(keeper.poll(), Health::Running);

        // A new daemon instance: the next request launches a new session and uses it.
        keeper.daemon.up = Some(B);
        assert_eq!(
            keeper.ensure().unwrap(),
            "ws://127.0.0.1:9/devtools/browser/2"
        );
        assert_eq!(
            lock(&journal).launched,
            [1, 2],
            "two launches, both through the daemon"
        );
        assert_eq!(
            calls_to(&journal, 1),
            calls_before,
            "the old session is never used again"
        );
        assert_eq!(calls_to(&journal, 2), 1);
        assert!(
            lock(&journal).revoked.is_empty(),
            "nothing to revoke: the broker had exited"
        );
    }

    /// The broker's exit is noticed during a request too (no poll in between), and a daemon that
    /// is back already serves that same request.
    #[test]
    fn a_request_on_a_lost_session_re_establishes_it_when_the_daemon_changed() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        broker_exits(&keeper, 1);
        keeper.daemon.up = Some(B);
        assert_eq!(
            keeper.ensure().unwrap(),
            "ws://127.0.0.1:9/devtools/browser/2"
        );
        assert_eq!(lock(&journal).launched, [1, 2]);
    }

    /// A broker that says its session is no longer valid (its capability is refused: a daemon
    /// that restarted while the broker survived) is dropped; the new daemon launches a new one.
    #[test]
    fn a_broker_whose_capability_is_refused_is_replaced_not_reused() {
        let journal = Arc::new(Mutex::new(Journal::default()));
        let mut daemon = FakeDaemon::new(&journal);
        daemon.replies.push_back(Ok(BrokerReply::SessionGone(
            "capability proof does not match an active principal session".into(),
        )));
        let mut keeper = SessionKeeper::start(daemon, LOST_GRACE).unwrap_or_else(|_| panic!());
        keeper.daemon.up = Some(B);
        assert_eq!(
            keeper.ensure().unwrap(),
            "ws://127.0.0.1:9/devtools/browser/2"
        );
        assert_eq!(
            calls_to(&journal, 1),
            1,
            "the old broker was asked once, never again"
        );
        keeper.ensure().unwrap();
        assert_eq!(calls_to(&journal, 1), 1);
        assert_eq!(calls_to(&journal, 2), 2);
    }

    /// A daemon that cannot say why the session ended (it predates `SessionEnd`, or forgot the
    /// session) keeps the earlier behaviour: undecided (`session_lost`) for the grace period,
    /// then the wrapper ends. An unknown reason never renews.
    #[test]
    fn an_unknown_end_reason_ends_the_wrapper_after_the_grace_period() {
        let (mut keeper, journal) = keeper(Duration::from_millis(200));
        assert_eq!(keeper.daemon.end, SessionEnd::Unknown);
        broker_exits(&keeper, 1);
        assert_eq!(keeper.poll(), Health::Running);
        assert_eq!(keeper.state_name(), "lost");
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_lost"));

        std::thread::sleep(Duration::from_millis(250));
        assert!(matches!(keeper.poll(), Health::Ended(m) if m.contains("does not say why")));
        let err = keeper.ensure().unwrap_err();
        assert_eq!(err.class, Some("session_ended"), "{err:?}");
        // Even if the daemon later restarts, an ended wrapper stays ended.
        keeper.daemon.up = Some(B);
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_ended"));
        assert_eq!(lock(&journal).launched, [1], "no second session");
    }

    /// The daemon says the session expired: the next browser request launches a new one through
    /// the daemon (no grace period, no guessing), and nothing of the old one is used again.
    #[test]
    fn an_expired_session_is_renewed_on_the_next_request() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        keeper.ensure().unwrap();
        keeper.daemon.end = SessionEnd::Ended(SessionEndReason::Expired);
        broker_exits(&keeper, 1);
        assert_eq!(
            keeper.poll(),
            Health::Running,
            "expiry does not end the wrapper"
        );
        assert_eq!(keeper.state_name(), "idle");
        assert_eq!(lock(&journal).launched, [1], "renewal is lazy");
        let calls_before = calls_to(&journal, 1);

        assert_eq!(
            keeper.ensure().unwrap(),
            "ws://127.0.0.1:9/devtools/browser/2"
        );
        assert_eq!(lock(&journal).launched, [1, 2]);
        assert_eq!(
            calls_to(&journal, 1),
            calls_before,
            "the expired session is never reused"
        );
        assert!(lock(&journal).revoked.is_empty());

        // The renewed session served, so its own expiry is renewed too (once per expiry).
        broker_exits(&keeper, 2);
        keeper.ensure().unwrap();
        assert_eq!(lock(&journal).launched, [1, 2, 3]);
    }

    /// The expiry is also noticed during a request (no poll in between): that request renews.
    #[test]
    fn a_request_on_an_expired_session_renews_it() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        keeper.daemon.end = SessionEnd::Ended(SessionEndReason::Expired);
        broker_exits(&keeper, 1);
        assert_eq!(
            keeper.ensure().unwrap(),
            "ws://127.0.0.1:9/devtools/browser/2"
        );
        assert_eq!(lock(&journal).launched, [1, 2]);
    }

    /// Every deliberate end the daemon records (revoked, terminated, profile disabled), and an
    /// exit or a reason this build does not know, ends the wrapper at once, with no new session.
    #[test]
    fn a_deliberate_end_ends_the_wrapper() {
        for (reason, says) in [
            (SessionEndReason::Revoked, "revoked"),
            (SessionEndReason::Terminated, "terminated"),
            (SessionEndReason::ProfileDisabled, "profile was disabled"),
            (SessionEndReason::Exited, "process exited"),
            (SessionEndReason::ClientGone, "client is gone"),
            (SessionEndReason::Unknown, "does not know"),
        ] {
            let (mut keeper, journal) = keeper(LOST_GRACE);
            keeper.daemon.end = SessionEnd::Ended(reason);
            broker_exits(&keeper, 1);
            match keeper.poll() {
                Health::Ended(message) => assert!(message.contains(says), "{reason:?}: {message}"),
                other => panic!("{reason:?}: {other:?}"),
            }
            let err = keeper.ensure().unwrap_err();
            assert_eq!(err.class, Some("session_ended"), "{reason:?}");
            keeper.daemon.up = Some(B);
            assert_eq!(keeper.ensure().unwrap_err().class, Some("session_ended"));
            assert_eq!(lock(&journal).launched, [1], "{reason:?}: no new session");
        }
    }

    /// A session the daemon still lists as running (its end not recorded yet) is undecided; once
    /// the daemon records the expiry, it is renewed.
    #[test]
    fn an_end_not_recorded_yet_waits_for_the_reason() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        keeper.daemon.end = SessionEnd::Running;
        broker_exits(&keeper, 1);
        assert_eq!(keeper.poll(), Health::Running);
        assert_eq!(keeper.state_name(), "lost");
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_lost"));
        keeper.daemon.end = SessionEnd::Ended(SessionEndReason::Expired);
        keeper.ensure().unwrap();
        assert_eq!(lock(&journal).launched, [1, 2]);
    }

    /// Loop protection: a renewed session that expires before it handed out a single endpoint
    /// (a `max_session_ttl` too short to use) is not renewed again; the wrapper stops. And one
    /// request never launches more than one session.
    #[test]
    fn a_renewal_that_expires_before_use_is_not_renewed_again() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        keeper.daemon.end = SessionEnd::Ended(SessionEndReason::Expired);
        broker_exits(&keeper, 1);
        // The renewal's broker is gone before it answers its first request.
        keeper.daemon.replies.push_back(Err(LinkLost::Closed));
        let err = keeper.ensure().unwrap_err();
        assert_eq!(err.class, Some("session_ended"), "{err:?}");
        assert!(err.message.contains("too short"), "{err:?}");
        assert_eq!(lock(&journal).launched, [1, 2], "one renewal, then stop");
        assert!(matches!(keeper.poll(), Health::Ended(_)));
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_ended"));
        assert_eq!(lock(&journal).launched, [1, 2]);
    }

    /// A request whose fresh session is gone at once (the daemon has not said why yet) does not
    /// launch a second one in the same request.
    #[test]
    fn one_request_launches_at_most_one_session() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        keeper.daemon.up = None;
        broker_exits(&keeper, 1);
        keeper.poll();
        keeper.daemon.up = Some(B);
        keeper.daemon.end = SessionEnd::Running;
        keeper.daemon.replies.push_back(Err(LinkLost::Closed));
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_lost"));
        assert_eq!(lock(&journal).launched, [1, 2]);
    }

    /// A daemon that accepts the connection but does not answer (shutting down) is undecided,
    /// even past the grace period; once it is gone a new session is allowed.
    #[test]
    fn a_silent_daemon_is_undecided_until_it_is_gone() {
        let (mut keeper, journal) = keeper(Duration::ZERO);
        broker_exits(&keeper, 1);
        keeper.daemon.silent = true;
        assert_eq!(keeper.poll(), Health::Running);
        assert_eq!(keeper.state_name(), "lost");
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_lost"));
        keeper.daemon.silent = false;
        keeper.daemon.up = None;
        assert_eq!(keeper.poll(), Health::Running);
        assert_eq!(keeper.state_name(), "idle");
        assert_eq!(lock(&journal).launched, [1]);
    }

    /// A link that broke (no answer in time, garbage) may still have a live broker: its session
    /// is revoked first. The wrapper ended that session itself, so it launches a new one.
    #[test]
    fn a_broken_link_revokes_its_session_and_starts_a_new_one() {
        let journal = Arc::new(Mutex::new(Journal::default()));
        let mut daemon = FakeDaemon::new(&journal);
        daemon.replies.push_back(Err(LinkLost::Broken));
        let mut keeper = SessionKeeper::start(daemon, Duration::ZERO).unwrap_or_else(|_| panic!());
        assert_eq!(
            keeper.ensure().unwrap(),
            "ws://127.0.0.1:9/devtools/browser/2"
        );
        assert_eq!(lock(&journal).revoked, [1]);
        assert_eq!(lock(&journal).launched, [1, 2]);
        assert_eq!(
            calls_to(&journal, 1),
            1,
            "the broken link is never used again"
        );
    }

    /// ...but when the daemon no longer had that session (it ended it itself), the live daemon
    /// decided, and no new session is launched.
    #[test]
    fn a_broken_link_to_a_session_the_daemon_ended_ends_the_wrapper() {
        let journal = Arc::new(Mutex::new(Journal::default()));
        let mut daemon = FakeDaemon::new(&journal);
        daemon.replies.push_back(Err(LinkLost::Broken));
        daemon.forgot = true;
        let mut keeper = SessionKeeper::start(daemon, Duration::ZERO).unwrap_or_else(|_| panic!());
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_ended"));
        assert_eq!(lock(&journal).revoked, [1]);
        assert_eq!(lock(&journal).launched, [1]);
    }

    /// A refusal (pipe mode, a held port) keeps the session; the message is the daemon's.
    #[test]
    fn a_refusal_keeps_the_session() {
        let journal = Arc::new(Mutex::new(Journal::default()));
        let mut daemon = FakeDaemon::new(&journal);
        daemon.replies.push_back(Ok(BrokerReply::Refused(
            "protocol error: Playwright browser discovery requires browser_cdp_expose = 'port'"
                .into(),
        )));
        let mut keeper = SessionKeeper::start(daemon, LOST_GRACE).unwrap_or_else(|_| panic!());
        let err = keeper.ensure().unwrap_err();
        assert_eq!(err.class, None, "classified from the daemon's text");
        assert!(
            err.message.contains("requires browser_cdp_expose"),
            "{err:?}"
        );
        assert_eq!(keeper.state_name(), "live");
        keeper.ensure().unwrap();
        assert_eq!(lock(&journal).launched, [1]);
    }

    /// A relaunch the daemon refuses for now (its session limit is full) says so and retries on
    /// the next request.
    #[test]
    fn a_refused_relaunch_is_reported_and_retried() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        keeper.daemon.up = None;
        broker_exits(&keeper, 1);
        keeper.poll();
        keeper.daemon.up = Some(B);
        keeper.daemon.refuse = Some(("session limit reached".into(), false));
        let err = keeper.ensure().unwrap_err();
        assert!(err.message.contains("session limit"), "{err:?}");
        keeper.daemon.refuse = None;
        keeper.ensure().unwrap();
        assert_eq!(lock(&journal).launched, [1, 2]);
    }

    /// A relaunch refused for the profile itself (disabled or removed while the daemon was
    /// restarting) ends the wrapper.
    #[test]
    fn a_relaunch_refused_for_the_profile_ends_the_wrapper() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        keeper.daemon.up = None;
        broker_exits(&keeper, 1);
        keeper.poll();
        keeper.daemon.up = Some(B);
        keeper.daemon.refuse = Some(("profile 'agent' is disabled".into(), true));
        let err = keeper.ensure().unwrap_err();
        assert_eq!(err.class, Some("session_ended"), "{err:?}");
        assert!(err.message.contains("disabled"), "{err:?}");
        assert!(matches!(keeper.poll(), Health::Ended(_)));
        keeper.daemon.refuse = None;
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_ended"));
        assert_eq!(lock(&journal).launched, [1]);
    }

    #[test]
    fn a_profile_run_as_another_user_is_not_kept_here() {
        let journal = Arc::new(Mutex::new(Journal::default()));
        let mut daemon = FakeDaemon::new(&journal);
        daemon.foreign = true;
        assert!(matches!(
            SessionKeeper::start(daemon, LOST_GRACE),
            Err(LaunchError::ForeignUser { .. })
        ));
    }

    #[test]
    fn shutdown_closes_the_link_and_revokes_when_asked() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        keeper.shutdown(true);
        assert_eq!(lock(&journal).revoked, [1]);
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_ended"));
    }

    /// The real admin daemon over a runtime directory where nothing listens: the launch and the
    /// probe fail at once.
    #[test]
    fn a_missing_daemon_fails_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = AdminDaemon {
            profile: ProfileId::new("agent").unwrap(),
            argv: broker_argv(Path::new("/usr/bin/passless"), "agent", None),
            base: Some(dir.path().to_path_buf()),
        };
        let started = Instant::now();
        assert!(matches!(daemon.launch(), Err(LaunchError::Unreachable(_))));
        assert_eq!(daemon.probe(), Probe::Down);
        assert!(!daemon.revoke(&PrincipalSessionId::new()));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn the_broker_command_line_names_the_profile_and_url_only() {
        assert_eq!(
            broker_argv(
                Path::new("/usr/bin/passless"),
                "coding",
                Some("https://a.test/")
            ),
            [
                "/usr/bin/passless",
                "agent",
                "mcp-session-broker",
                "--profile",
                "coding",
                "--url",
                "https://a.test/"
            ]
        );
        assert_eq!(
            broker_argv(Path::new("/usr/bin/passless"), "coding", None).len(),
            5
        );
    }

    /// A broker on one end of a socketpair, the real link on the other.
    fn broker_pair(
        mut handle_request: impl FnMut(BrokerRequest) -> BrokerMessage + Send + 'static,
    ) -> (BrokerLink, std::thread::JoinHandle<Result<()>>) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut output = theirs.try_clone().unwrap();
            serve(theirs, &mut output, (7, 8), &|| true, &mut handle_request)
        });
        (
            BrokerLink::new(ours, Duration::from_secs(5)).unwrap(),
            handle,
        )
    }

    #[test]
    fn the_link_and_the_broker_speak_the_same_protocol() {
        let mut answers = vec![
            BrokerMessage::Failed {
                message: "policy denied".into(),
                session_gone: false,
            },
            BrokerMessage::Ensured {
                endpoint: "ws://127.0.0.1:9/devtools/browser/x".into(),
            },
        ];
        let (mut link, broker) = broker_pair(move |_| answers.pop().unwrap());
        assert_eq!(
            link.hello(Duration::from_secs(5)),
            Ok((BROKER_PROTOCOL, 7, 8))
        );
        assert_eq!(link.lost(), None);
        assert_eq!(
            link.ensure(),
            Ok(BrokerReply::Endpoint(
                "ws://127.0.0.1:9/devtools/browser/x".into()
            ))
        );
        assert_eq!(
            link.ensure(),
            Ok(BrokerReply::Refused("policy denied".into()))
        );
        // The wrapper closes the link: the broker exits cleanly.
        drop(link);
        broker.join().unwrap().unwrap();
    }

    #[test]
    fn a_broker_whose_session_is_gone_says_so_and_exits() {
        let (mut link, broker) = broker_pair(|_| BrokerMessage::Failed {
            message: "the passless daemon is not running".into(),
            session_gone: true,
        });
        link.hello(Duration::from_secs(5)).unwrap();
        assert_eq!(
            link.ensure(),
            Ok(BrokerReply::SessionGone(
                "the passless daemon is not running".into()
            ))
        );
        assert!(broker.join().unwrap().is_err());
        // Its exit is the link's EOF, seen without a request. (A process forked by another test
        // at this very moment may hold the broker's end of the socket until its exec: wait it
        // out.)
        let deadline = Instant::now() + Duration::from_secs(5);
        while link.lost().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(link.lost(), Some(LinkLost::Closed));
        assert_eq!(link.ensure(), Err(LinkLost::Closed));
    }

    /// Between requests: silence is fine, data nobody asked for is a broken link (whose session
    /// gets revoked), EOF a gone broker.
    #[test]
    fn the_link_tells_a_gone_broker_from_a_broken_one() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let mut link = BrokerLink::new(ours, Duration::from_secs(1)).unwrap();
        assert_eq!(link.lost(), None);
        (&theirs).write_all(b"{}\n").unwrap();
        assert_eq!(link.lost(), Some(LinkLost::Broken));

        let (ours, theirs) = UnixStream::pair().unwrap();
        let mut link = BrokerLink::new(ours, Duration::from_secs(1)).unwrap();
        drop(theirs);
        assert_eq!(link.lost(), Some(LinkLost::Closed));
    }

    /// A broker that never answers costs at most the link's timeout.
    #[test]
    fn an_unanswered_request_is_bounded() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let mut link = BrokerLink::new(ours, Duration::from_millis(300)).unwrap();
        let started = Instant::now();
        assert_eq!(link.ensure(), Err(LinkLost::Broken));
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(theirs);
    }

    #[test]
    fn the_broker_refuses_garbage_and_watches_its_parent() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut output = theirs.try_clone().unwrap();
            serve(theirs, &mut output, (1, 1), &|| true, &mut |_| {
                unreachable!("no request is valid")
            })
        });
        let mut writer = ours.try_clone().unwrap();
        writer.write_all(b"{\"op\":\"exec\"}\n").unwrap();
        assert!(
            handle.join().unwrap().is_err(),
            "an unknown request ends the broker"
        );

        // An orphaned broker (its daemon is gone) exits on its own.
        let (_ours, theirs) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let mut output = theirs.try_clone().unwrap();
        let err = serve(
            theirs,
            &mut output,
            (1, 1),
            &|| false,
            &mut |_| unreachable!(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("daemon that launched"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(ours);
    }

    fn access_call(rp_id: &str) -> AccessCall {
        AccessCall {
            rp_id: rp_id.into(),
            action: GrantAction::Register,
            note: Some("why".into()),
            wait_ms: 5_000,
        }
    }

    fn access_status(
        state: passless_core::agent::protocol::AccessRequestState,
    ) -> AccessRequestStatus {
        AccessRequestStatus {
            state,
            rp_id: "example.org".into(),
            action: GrantAction::Register,
            expires_in_secs: Some(597),
            retry_after_secs: None,
            message: "m".into(),
        }
    }

    /// Broker protocol 2: a request for access crosses the link as one line each way and maps to
    /// the same `PrincipalRequest` fields; every state is an answer, a refusal is not.
    #[test]
    fn a_request_for_access_crosses_the_link_and_every_state_is_an_answer() {
        use passless_core::agent::protocol::AccessRequestState;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_broker = Arc::clone(&seen);
        let mut answers = vec![
            BrokerMessage::Failed {
                message: "malformed".into(),
                session_gone: false,
            },
            BrokerMessage::AccessRequest {
                status: access_status(AccessRequestState::Pending),
            },
            BrokerMessage::AccessRequest {
                status: access_status(AccessRequestState::Approved),
            },
        ];
        let (mut link, broker) = broker_pair(move |request| {
            lock(&seen_by_broker).push(request);
            answers.pop().unwrap()
        });
        link.hello(Duration::from_secs(5)).unwrap();
        assert_eq!(
            link.request_access(&access_call("example.org")),
            Ok(BrokerReply::Access(access_status(
                AccessRequestState::Approved
            )))
        );
        assert_eq!(
            link.request_access(&access_call("example.org")),
            Ok(BrokerReply::Access(access_status(
                AccessRequestState::Pending
            )))
        );
        assert_eq!(
            link.request_access(&access_call("example.org")),
            Ok(BrokerReply::Refused("malformed".into()))
        );
        // The broker got the call's fields, with the wait in milliseconds, and the same link
        // still serves an ensure.
        assert_eq!(
            lock(&seen)[0],
            BrokerRequest::RequestAccess {
                rp_id: "example.org".into(),
                action: GrantAction::Register,
                note: Some("why".into()),
                wait_ms: Some(5_000),
            }
        );
        drop(link);
        broker.join().unwrap().unwrap();
    }

    /// The wire form of the new request, and that a version 1 wrapper's `"ensure"` is unchanged.
    #[test]
    fn the_broker_requests_have_a_stable_wire_form() {
        assert_eq!(
            serde_json::to_string(&BrokerRequest::Ensure).unwrap(),
            r#""ensure""#
        );
        let request = BrokerRequest::RequestAccess {
            rp_id: "example.org".into(),
            action: GrantAction::Authenticate,
            note: None,
            wait_ms: Some(0),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            json,
            r#"{"request_access":{"rp_id":"example.org","action":"authenticate","wait_ms":0}}"#
        );
        assert_eq!(
            serde_json::from_str::<BrokerRequest>(&json).unwrap(),
            request
        );
        for bad in [
            r#"{"request_access":{"rp_id":"a.b","action":"authenticate","extra":1}}"#,
            r#"{"request_access":{"action":"authenticate"}}"#,
            r#"{"exec":{}}"#,
        ] {
            assert!(serde_json::from_str::<BrokerRequest>(bad).is_err(), "{bad}");
        }
    }

    /// A broker of protocol 1 (an older passless under a running MCP server, or the reverse) is
    /// refused for good with a message that says what to do; so is a foreign Unix user.
    #[test]
    fn a_broker_of_another_protocol_is_refused_cleanly() {
        assert_eq!(check_hello((BROKER_PROTOCOL, 5, 6), (5, 6)), Ok(()));
        let Err(LaunchError::Refused { message, fatal }) = check_hello((1, 5, 6), (5, 6)) else {
            panic!("a protocol 1 broker is refused");
        };
        assert!(fatal);
        assert!(message.contains("broker protocol 1"), "{message}");
        assert!(message.contains("restart the MCP server"), "{message}");
        assert!(matches!(
            check_hello((BROKER_PROTOCOL + 1, 5, 6), (5, 6)),
            Err(LaunchError::Refused { fatal: true, .. })
        ));
        assert_eq!(
            check_hello((BROKER_PROTOCOL, 7, 8), (5, 6)),
            Err(LaunchError::ForeignUser { uid: 7, gid: 8 })
        );
        // A hello of the old protocol is read as one: the wrapper learns the version, whatever
        // else the line says.
        let (mut link, broker) = broker_pair(|_| unreachable!());
        link.hello(Duration::from_secs(5)).unwrap();
        drop(link);
        broker.join().unwrap().unwrap();
    }

    /// A request for access goes through the same session handling as an ensure: it uses the live
    /// session, and a session that expired or whose daemon restarted is re-established by it.
    #[test]
    fn a_request_for_access_uses_and_re_establishes_the_session_like_an_ensure() {
        use passless_core::agent::protocol::AccessRequestState;
        let (mut keeper, journal) = keeper(LOST_GRACE);
        let status = keeper.request_access(&access_call("example.org")).unwrap();
        assert_eq!(status.state, AccessRequestState::Approved);
        assert_eq!(status.message, "approved through session 1");
        assert_eq!(keeper.state_name(), "live");
        // It did not count as handing out an endpoint: `served` is for the renewal limit.
        assert_eq!(calls_to(&journal, 1), 0, "no ensure was sent");

        // The broker's daemon is replaced: the next request re-establishes the session.
        broker_exits(&keeper, 1);
        keeper.daemon.up = Some(B);
        let status = keeper.request_access(&access_call("example.org")).unwrap();
        assert_eq!(status.message, "approved through session 2");
        assert_eq!(lock(&journal).launched, [1, 2]);

        // A refusal keeps the session, and an ensure after it still works.
        keeper.daemon.replies = VecDeque::new();
        if let State::Live { link, .. } = &mut keeper.state {
            link.replies
                .push_back(Ok(BrokerReply::Refused("the daemon said no".into())));
        }
        let error = keeper
            .request_access(&access_call("example.org"))
            .unwrap_err();
        assert_eq!(error.message, "the daemon said no");
        assert_eq!(keeper.state_name(), "live");
        assert!(keeper.ensure().is_ok());
    }

    #[test]
    fn an_ensure_that_gets_an_access_answer_is_a_protocol_error() {
        let (mut keeper, _journal) = keeper(LOST_GRACE);
        if let State::Live { link, .. } = &mut keeper.state {
            link.replies.push_back(Ok(BrokerReply::Access(access_status(
                passless_core::agent::protocol::AccessRequestState::Approved,
            ))));
        }
        let error = keeper.ensure().unwrap_err();
        assert!(error.message.contains("another kind"), "{}", error.message);
    }

    #[test]
    fn lines_are_bounded() {
        let long = vec![b'a'; MAX_LINE as usize + 10];
        let mut reader = BufReader::new(&long[..]);
        assert!(read_line(&mut reader).is_err());
        let mut reader = BufReader::new(&b"no newline"[..]);
        assert!(read_line(&mut reader).is_err());
        let mut reader = BufReader::new(&b"\"ensure\"\n"[..]);
        assert_eq!(read_line(&mut reader).unwrap().unwrap(), b"\"ensure\"");
        assert_eq!(read_line(&mut reader).unwrap(), None);
    }

    #[test]
    fn a_session_is_gone_only_for_errors_that_say_so() {
        use passless_core::agent::protocol::{ProtocolError, RecommendedAction};
        let protocol =
            |code| ClientError::Protocol(ProtocolError::new(code, "x", RecommendedAction::Abort));
        assert!(session_gone(&ClientError::DaemonNotRunning {
            socket: PathBuf::from("/x")
        }));
        assert!(session_gone(&protocol(ErrorCode::Unauthorized)));
        assert!(!session_gone(&protocol(ErrorCode::Forbidden)));
        assert!(!session_gone(&protocol(ErrorCode::Conflict)));
        assert!(!session_gone(&ClientError::Timeout));
    }
}
