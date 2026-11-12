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
//! - a session the live daemon ended (revoked, expired, its grants revoked, its profile disabled)
//!   is not re-established: the wrapper exits, as it did before. Only a session lost with its
//!   daemon instance (the daemon is gone, or another daemon process answers) is re-established,
//!   lazily, on the next browser tool call, and one the wrapper revoked itself (its broker did not
//!   answer in time, or broke the protocol);
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

use passless_core::agent::protocol::{AdminRequest, AdminResponse, ErrorCode};
use passless_core::agent::{PrincipalRequest, PrincipalResponse, PrincipalSessionId, ProfileId};
use passless_core::{Error, Result};

use serde::{Deserialize, Serialize};

use crate::agent::cdp_bootstrap::{CdpBootstrap, EnsureError};
use crate::agent::client::{
    AdminClient, ClientError, DaemonInstance, PrincipalClient, resolve_runtime_base,
};

/// The hidden subcommand the wrapper launches as its principal session.
const BROKER_SUBCOMMAND: &str = "mcp-session-broker";
/// The broker protocol (one JSON object per line). A broker of another version is refused.
const BROKER_PROTOCOL: u32 = 1;
/// Bounds on admin requests: a launch, and the cheap ones (probe, revoke).
const ADMIN_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a new broker may take to say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(15);
/// How long one "ensure the browser" may take: a launch waits up to 30 s for the extension.
const ENSURE_TIMEOUT: Duration = Duration::from_secs(90);
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
#[serde(rename_all = "snake_case")]
enum BrokerRequest {
    Ensure,
}

/// What the broker says, one line each.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BrokerMessage {
    /// The first line: the protocol and the Unix user the session runs as.
    Hello { protocol: u32, uid: u32, gid: u32 },
    /// The managed browser's CDP websocket endpoint.
    Ensured { endpoint: String },
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
        &mut || broker_ensure(profile, url),
    )
}

/// The broker's loop: hello, then one answer per request, until the wrapper closes the link (`Ok`)
/// or the session or its daemon is gone (`Err`).
fn serve<R: Read + AsRawFd, W: Write>(
    input: R,
    output: &mut W,
    (uid, gid): (u32, u32),
    parented: &dyn Fn() -> bool,
    ensure: &mut dyn FnMut() -> BrokerMessage,
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
        match request {
            BrokerRequest::Ensure => {
                let reply = ensure();
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
    /// The daemon answered and refused, or the session did not start.
    Refused(String),
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
    /// Revoke a session; `true` when this revocation ended it (the daemon still had it).
    fn revoke(&mut self, session: &Self::Session) -> bool;
}

pub(crate) trait Link {
    fn ensure(&mut self) -> std::result::Result<BrokerReply, LinkLost>;
    /// Without blocking: whether the broker went away (`Closed`) or spoke unasked (`Broken`)
    /// since the last request.
    fn lost(&mut self) -> Option<LinkLost>;
}

enum State<L, S> {
    Live {
        link: L,
        instance: Option<DaemonInstance>,
        session: S,
    },
    /// The session is gone; `instance` launched it.
    Lost {
        instance: Option<DaemonInstance>,
        since: Instant,
    },
    /// No session, and launching one is allowed: the next browser request does.
    Idle,
    /// The daemon that launched the session ended it: no new one.
    Ended,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Health {
    Running,
    /// The live daemon ended the session; the wrapper exits.
    Ended,
}

enum Resolution {
    /// The daemon is down: the next request launches when it is back.
    Down,
    /// Another daemon instance answers: launch now.
    Restarted,
    /// The same instance still answers (or nobody answers yet): undecided.
    Pending,
    /// The same instance kept answering past the grace period: it ended the session.
    Ended,
}

/// The wrapper's principal session: launched at start, re-established after its daemon went
/// away, never after the live daemon ended it.
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
            state: live(launched),
            grace,
        })
    }

    /// The managed browser's endpoint, from the current session's broker, after re-establishing
    /// the session if its daemon went away. Never blocks beyond the admin and link timeouts.
    pub(crate) fn ensure(&mut self) -> std::result::Result<String, EnsureError> {
        // Enough for: a lost link, a probe, a launch and the request on the new link.
        for _ in 0..4 {
            match std::mem::replace(&mut self.state, State::Idle) {
                State::Live {
                    mut link,
                    instance,
                    session,
                } => match link.ensure() {
                    Ok(BrokerReply::Endpoint(endpoint)) => {
                        self.state = State::Live {
                            link,
                            instance,
                            session,
                        };
                        return Ok(endpoint);
                    }
                    Ok(BrokerReply::Refused(message)) => {
                        self.state = State::Live {
                            link,
                            instance,
                            session,
                        };
                        return Err(EnsureError::from(message));
                    }
                    Ok(BrokerReply::SessionGone(_)) | Err(LinkLost::Closed) => {
                        self.lose(link, instance, None);
                    }
                    Err(LinkLost::Broken) => self.lose(link, instance, Some(session)),
                },
                State::Lost { instance, since } => {
                    self.state = State::Lost { instance, since };
                    match self.resolve() {
                        Resolution::Restarted => {}
                        Resolution::Down => return Err(unavailable("it does not answer")),
                        Resolution::Pending => return Err(session_lost()),
                        Resolution::Ended => return Err(session_ended()),
                    }
                }
                State::Idle => match self.daemon.launch() {
                    Ok(launched) => self.state = live(launched),
                    Err(LaunchError::Unreachable(detail)) => return Err(unavailable(&detail)),
                    Err(LaunchError::Refused(message)) => return Err(EnsureError::from(message)),
                    Err(LaunchError::ForeignUser { uid, gid }) => {
                        // The profile changed under a running wrapper: its server would have to
                        // run as that user now.
                        self.state = State::Ended;
                        return Err(EnsureError::new(
                            "session_ended",
                            format!(
                                "the profile's principal sessions now run as uid {uid} gid {gid}, \
                                 not as this MCP server's user; restart the MCP server"
                            ),
                        ));
                    }
                },
                State::Ended => {
                    self.state = State::Ended;
                    return Err(session_ended());
                }
            }
        }
        Err(unavailable("the session could not be re-established"))
    }

    /// Notice a lost session between requests (the wrapper polls this), and tell whether the
    /// live daemon ended it.
    pub(crate) fn poll(&mut self) -> Health {
        if let State::Live { link, .. } = &mut self.state
            && let Some(how) = link.lost()
            && let State::Live {
                link,
                instance,
                session,
            } = std::mem::replace(&mut self.state, State::Idle)
        {
            // Data nobody asked for is a protocol violation: that broker may still run.
            let revoke = (how == LinkLost::Broken).then_some(session);
            self.lose(link, instance, revoke);
        }
        if matches!(self.state, State::Lost { .. }) {
            self.resolve();
        }
        match self.state {
            State::Ended => Health::Ended,
            _ => Health::Running,
        }
    }

    /// Close the link (the broker exits on its EOF), revoking the session too when asked.
    pub(crate) fn shutdown(&mut self, revoke: bool) {
        if let State::Live { link, session, .. } = std::mem::replace(&mut self.state, State::Ended)
        {
            drop(link);
            if revoke {
                let _ = self.daemon.revoke(&session);
            }
        }
    }

    /// Drop a link that is no longer usable. A broker that may still run is revoked (closing the
    /// link also makes it exit): when that revocation is what ended the session, the wrapper
    /// ended it, and a new one may be launched. Otherwise (the broker closed the link, or the
    /// daemon no longer knew the session) the session is lost, and [`Self::resolve`] decides why.
    fn lose(
        &mut self,
        link: D::Link,
        instance: Option<DaemonInstance>,
        revoke: Option<D::Session>,
    ) {
        drop(link);
        if let Some(session) = revoke
            && self.daemon.revoke(&session)
        {
            self.state = State::Idle;
            return;
        }
        self.state = State::Lost {
            instance,
            since: Instant::now(),
        };
    }

    /// Decide what a lost session means: its daemon went away (re-establish), or the live daemon
    /// ended it (do not).
    fn resolve(&mut self) -> Resolution {
        let State::Lost { instance, since } = self.state else {
            return Resolution::Pending;
        };
        let resolution = match self.daemon.probe() {
            Probe::Down => Resolution::Down,
            Probe::Answering(Some(now)) if instance != Some(now) => Resolution::Restarted,
            Probe::Answering(_) if since.elapsed() >= self.grace => Resolution::Ended,
            Probe::Answering(_) | Probe::Silent => Resolution::Pending,
        };
        match resolution {
            Resolution::Down | Resolution::Restarted => self.state = State::Idle,
            Resolution::Ended => self.state = State::Ended,
            Resolution::Pending => {}
        }
        resolution
    }

    #[cfg(test)]
    fn state_name(&self) -> &'static str {
        match self.state {
            State::Live { .. } => "live",
            State::Lost { .. } => "lost",
            State::Idle => "idle",
            State::Ended => "ended",
        }
    }
}

fn live<L, S>(launched: Launched<L, S>) -> State<L, S> {
    State::Live {
        link: launched.link,
        instance: launched.instance,
        session: launched.session,
    }
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
        "the principal session ended while its daemon still answers; checking whether the \
         daemon is restarting",
    )
}

fn session_ended() -> EnsureError {
    EnsureError::new(
        "session_ended",
        "the daemon ended this MCP server's principal session (revoked, expired, its grants \
         revoked or its profile disabled); it is not re-established",
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
        let (ours, theirs) = UnixStream::pair()
            .map_err(|e| LaunchError::Refused(format!("cannot create the broker link: {e}")))?;
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
                return Err(LaunchError::Refused(
                    "the daemon answered the session launch with an unexpected response".into(),
                ));
            }
            Err(ClientError::Protocol(e)) => {
                return Err(LaunchError::Refused(format!(
                    "the daemon refused the principal session: {e}"
                )));
            }
            Err(e) => return Err(LaunchError::Unreachable(e.to_string())),
        };
        let link = BrokerLink::new(ours, ENSURE_TIMEOUT);
        let hello = link
            .map_err(|_| LinkLost::Broken)
            .and_then(|mut link| link.hello(HELLO_TIMEOUT).map(|hello| (link, hello)));
        match hello {
            Ok((link, (BROKER_PROTOCOL, uid, gid))) if (uid, gid) == own_ids() => Ok(Launched {
                link,
                instance,
                session,
            }),
            Ok((link, (BROKER_PROTOCOL, uid, gid))) => {
                drop(link);
                let _ = self.revoke(&session);
                Err(LaunchError::ForeignUser { uid, gid })
            }
            Ok((link, (protocol, _, _))) => {
                drop(link);
                let _ = self.revoke(&session);
                Err(LaunchError::Refused(format!(
                    "the principal session speaks broker protocol {protocol}, this MCP server \
                     {BROKER_PROTOCOL} (passless was upgraded): restart the MCP server"
                )))
            }
            Err(_) => {
                let _ = self.revoke(&session);
                Err(LaunchError::Refused(
                    "the principal session started but its broker did not answer".to_string(),
                ))
            }
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

impl Link for BrokerLink {
    fn ensure(&mut self) -> std::result::Result<BrokerReply, LinkLost> {
        let mut request =
            serde_json::to_vec(&BrokerRequest::Ensure).map_err(|_| LinkLost::Broken)?;
        request.push(b'\n');
        self.writer.write_all(&request).map_err(|e| lost_by(&e))?;
        match self.receive(self.ensure_timeout)? {
            BrokerMessage::Ensured { endpoint } => Ok(BrokerReply::Endpoint(endpoint)),
            BrokerMessage::Failed {
                message,
                session_gone: true,
            } => Ok(BrokerReply::SessionGone(message)),
            BrokerMessage::Failed { message, .. } => Ok(BrokerReply::Refused(message)),
            BrokerMessage::Hello { .. } => Err(LinkLost::Broken),
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
        Err(LaunchError::Unreachable(message) | LaunchError::Refused(message)) => {
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
    let result = supervise(child_command, executable, &keeper);
    drop(bootstrap);
    result.map(Some)
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
) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        signal_hook::flag::register(signal, Arc::clone(&stop))
            .map_err(|e| Error::Other(format!("failed to register a signal handler: {e}")))?;
    }
    let parent = unsafe { libc::getppid() };
    let mut child = child_command.spawn().map_err(|e| {
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
            if health == Health::Ended {
                stop_child(&mut child);
                shutdown(keeper, false);
                return Err(Error::Other(format!(
                    "{}; stopped Playwright MCP",
                    session_ended().message
                )));
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
        refuse: Option<String>,
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
            if let Some(reason) = &self.refuse {
                return Err(LaunchError::Refused(reason.clone()));
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

    /// The live daemon ended the session (revocation, expiry): it is not re-established. While
    /// undecided the request fails as `session_lost`; past the grace period the wrapper ends.
    #[test]
    fn a_session_the_live_daemon_ended_is_not_re_established() {
        let (mut keeper, journal) = keeper(Duration::from_millis(200));
        broker_exits(&keeper, 1);
        assert_eq!(keeper.poll(), Health::Running);
        assert_eq!(keeper.state_name(), "lost");
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_lost"));

        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(keeper.poll(), Health::Ended);
        let err = keeper.ensure().unwrap_err();
        assert_eq!(err.class, Some("session_ended"), "{err:?}");
        // Even if the daemon later restarts, an ended wrapper stays ended.
        keeper.daemon.up = Some(B);
        assert_eq!(keeper.ensure().unwrap_err().class, Some("session_ended"));
        assert_eq!(lock(&journal).launched, [1], "no second session");
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

    /// A relaunch the daemon refuses (the profile was disabled meanwhile) says so and retries
    /// on the next request.
    #[test]
    fn a_refused_relaunch_is_reported_and_retried() {
        let (mut keeper, journal) = keeper(LOST_GRACE);
        keeper.daemon.up = None;
        broker_exits(&keeper, 1);
        keeper.poll();
        keeper.daemon.up = Some(B);
        keeper.daemon.refuse = Some("profile 'agent' is disabled".into());
        let err = keeper.ensure().unwrap_err();
        assert!(err.message.contains("disabled"), "{err:?}");
        keeper.daemon.refuse = None;
        keeper.ensure().unwrap();
        assert_eq!(lock(&journal).launched, [1, 2]);
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
        mut ensure: impl FnMut() -> BrokerMessage + Send + 'static,
    ) -> (BrokerLink, std::thread::JoinHandle<Result<()>>) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut output = theirs.try_clone().unwrap();
            serve(theirs, &mut output, (7, 8), &|| true, &mut ensure)
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
        let (mut link, broker) = broker_pair(move || answers.pop().unwrap());
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
        let (mut link, broker) = broker_pair(|| BrokerMessage::Failed {
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
        // Its exit is the link's EOF, seen without a request.
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
            serve(theirs, &mut output, (1, 1), &|| true, &mut || {
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
            &mut || unreachable!(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("daemon that launched"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(ours);
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
