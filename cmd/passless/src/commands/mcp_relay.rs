//! The opt-in stdio relay of `passless agent mcp playwright --with-access-tool` (ADR 0014
//! amendment section 6).
//!
//! Without the flag the Playwright MCP server inherits the client's stdio and none of this runs.
//! With it, the wrapper sits between the MCP client and the server and forwards newline-delimited
//! JSON-RPC in both directions **byte for byte**, except for two things:
//!
//! - the response that answers a client `tools/list` request without a `cursor`: the relay appends
//!   [`TOOL_NAME`] to `result.tools` (later pages are untouched, so pagination still works);
//! - a client `tools/call` whose `params.name` is [`TOOL_NAME`]: answered by the relay with the
//!   client's own `id` and never forwarded.
//!
//! The relay never originates a request to either side, so request ids cannot collide, and
//! `notifications/tools/list_changed` simply passes through (the client's re-list gets the tool
//! again). A line that does not parse as JSON is forwarded unchanged; so is one over
//! [`MAX_INSPECTED_LINE`], streamed without being held and never inspected. A batch (a JSON array)
//! is forwarded unchanged: MCP stopped sending them.
//!
//! The relay holds no capability and no bearer. It asks its [`AccessTool`] to run a call, which
//! reaches the daemon through the broker's principal session (or this process's own, when it runs
//! inside one). It is not part of the trust boundary, but a bug in it can break the MCP
//! connection, which is why it is opt-in and has its own tests.
//!
//! A tool call parks a worker thread until the daemon answers (at most `wait_seconds`, 120 at
//! most, plus the link's margin). At most [`MAX_IN_FLIGHT_CALLS`] calls run at once; the next one
//! is answered `busy` at once. Calls through one wrapper are serialized by its session keeper, so
//! a browser tool call that needs a (re-)discovery of the browser waits behind one that is waiting
//! for the human.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use passless_core::agent::protocol::{
    AccessRequestState, AccessRequestStatus, GrantAction, MAX_ACCESS_WAIT_MS, ProtocolError,
};

use serde_json::{Value, json};

/// The one tool the relay adds.
pub const TOOL_NAME: &str = "passless_request_access";
/// Lines longer than this are forwarded without being parsed.
pub const MAX_INSPECTED_LINE: usize = 4 * 1024 * 1024;
/// Tool calls the relay runs at once; the next one is answered `busy`.
pub const MAX_IN_FLIGHT_CALLS: usize = 4;
/// The longest note the tool accepts, in characters (the schema's `maxLength`).
const MAX_NOTE_CHARS: usize = 200;
/// The tool's default wait, in seconds (the schema's `default`).
const DEFAULT_WAIT_SECONDS: u64 = 30;
/// Pending `tools/list` ids the relay remembers before it forgets them all (a client that never
/// gets an answer must not grow it).
const MAX_PENDING_LISTS: usize = 1024;
/// How long [`RelayHandle::finish`] waits for the server's last output to reach the client.
const FINISH_WAIT: Duration = Duration::from_secs(2);

/// What a tool call asks the daemon for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessCall {
    pub rp_id: String,
    pub action: GrantAction,
    pub note: Option<String>,
    pub wait_ms: u64,
}

/// What the relay needs to run a call: an answer, or the error of a malformed call or a broken
/// link (the tool's result is then `isError`).
pub type ToolResult = Result<AccessRequestStatus, ProtocolError>;

/// The side that talks to the daemon.
pub trait AccessTool: Send + Sync + 'static {
    fn call(&self, call: AccessCall) -> ToolResult;
}

/// The tool as `tools/list` shows it (ADR 0014 amendment section 2.3).
pub fn tool_definition() -> Value {
    json!({
        "name": TOOL_NAME,
        "description": "Ask the human, through Passless, for passkey access to a site before you \
    navigate there. Use it when a site will need passkey sign-in or registration. The human sees a \
    fixed system prompt naming only the site and the action; your note is NOT shown to them, so \
    explain why in the chat. Approval does not sign in for you: navigate and use the site's normal \
    WebAuthn flow afterwards. For 'register' the approval is valid once, for 10 minutes, in this \
    browser only. The result's state says what happened; 'pending' means call again later with the \
    same arguments.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rp_id": { "type": "string", "description": "The site's RP ID, a domain such as example.com" },
                "action": { "type": "string", "enum": ["authenticate", "register"], "default": "authenticate" },
                "note": { "type": "string", "maxLength": MAX_NOTE_CHARS, "description": "Recorded in the audit log only" },
                "wait_seconds": { "type": "integer", "minimum": 0, "maximum": MAX_ACCESS_WAIT_MS / 1000, "default": DEFAULT_WAIT_SECONDS }
            },
            "required": ["rp_id"],
            "additionalProperties": false
        }
    })
}

/// A tool call's arguments, checked against the tool's input schema.
fn parse_arguments(arguments: &Value) -> Result<AccessCall, ProtocolError> {
    let empty = serde_json::Map::new();
    let object = match arguments {
        Value::Null => &empty,
        Value::Object(map) => map,
        _ => return Err(ProtocolError::malformed("arguments must be an object")),
    };
    if let Some(unknown) = object
        .keys()
        .find(|key| !["rp_id", "action", "note", "wait_seconds"].contains(&key.as_str()))
    {
        return Err(ProtocolError::malformed(format!(
            "unknown argument '{}' (the arguments are rp_id, action, note and wait_seconds)",
            unknown.chars().take(40).collect::<String>()
        )));
    }
    let rp_id = match object.get("rp_id") {
        Some(Value::String(rp_id)) if !rp_id.is_empty() => rp_id.clone(),
        _ => {
            return Err(ProtocolError::malformed(
                "rp_id is required: a non-empty string such as example.com",
            ));
        }
    };
    let action = match object.get("action") {
        None | Some(Value::Null) => GrantAction::Authenticate,
        Some(Value::String(action)) if action == "authenticate" => GrantAction::Authenticate,
        Some(Value::String(action)) if action == "register" => GrantAction::Register,
        _ => {
            return Err(ProtocolError::malformed(
                "action must be \"authenticate\" or \"register\"",
            ));
        }
    };
    let note = match object.get("note") {
        None | Some(Value::Null) => None,
        Some(Value::String(note)) if note.chars().count() <= MAX_NOTE_CHARS => Some(note.clone()),
        Some(Value::String(_)) => {
            return Err(ProtocolError::malformed(format!(
                "note is at most {MAX_NOTE_CHARS} characters"
            )));
        }
        _ => return Err(ProtocolError::malformed("note must be a string")),
    };
    let max_wait = MAX_ACCESS_WAIT_MS / 1000;
    let wait_seconds = match object.get("wait_seconds") {
        None | Some(Value::Null) => DEFAULT_WAIT_SECONDS,
        Some(value) => match value.as_u64() {
            Some(seconds) if seconds <= max_wait => seconds,
            _ => {
                return Err(ProtocolError::malformed(format!(
                    "wait_seconds must be an integer from 0 to {max_wait}"
                )));
            }
        },
    };
    Ok(AccessCall {
        rp_id,
        action,
        note,
        wait_ms: wait_seconds * 1000,
    })
}

/// What the relay does with one line from the client.
#[derive(Debug, PartialEq)]
pub enum ClientLine {
    /// Send it to the server unchanged.
    Forward,
    /// Answer it here: the request's id, and the tool call's `arguments`.
    Answer { id: Value, arguments: Value },
    /// A notification for the tool (it cannot be answered): drop it.
    Drop,
}

/// The shared state of one relay: the `tools/list` requests whose response must get the tool, and
/// the calls in flight.
pub struct Relay {
    tool: Arc<dyn AccessTool>,
    lists: Mutex<HashSet<String>>,
    in_flight: AtomicUsize,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The id of a JSON-RPC message in a form that compares (string and number ids stay distinct).
fn id_key(id: &Value) -> String {
    id.to_string()
}

impl Relay {
    pub fn new(tool: Arc<dyn AccessTool>) -> Self {
        Self {
            tool,
            lists: Mutex::new(HashSet::new()),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// Decide what to do with a client line (without its newline). Parses only a line that can be
    /// one of the two messages the relay cares about.
    pub fn classify_client_line(&self, line: &[u8]) -> ClientLine {
        let Ok(Value::Object(message)) = serde_json::from_slice::<Value>(line) else {
            return ClientLine::Forward;
        };
        let id = message.get("id").filter(|id| !id.is_null());
        match message.get("method").and_then(Value::as_str) {
            Some("tools/list") => {
                let first_page = message
                    .get("params")
                    .and_then(Value::as_object)
                    .is_none_or(|params| params.get("cursor").is_none_or(Value::is_null));
                if let (Some(id), true) = (id, first_page) {
                    let mut lists = lock(&self.lists);
                    if lists.len() >= MAX_PENDING_LISTS {
                        lists.clear();
                    }
                    lists.insert(id_key(id));
                }
                ClientLine::Forward
            }
            Some("tools/call") => {
                let params = message.get("params").and_then(Value::as_object);
                let named = params
                    .and_then(|params| params.get("name"))
                    .and_then(Value::as_str);
                if named != Some(TOOL_NAME) {
                    return ClientLine::Forward;
                }
                match id {
                    Some(id) => ClientLine::Answer {
                        id: id.clone(),
                        arguments: params
                            .and_then(|params| params.get("arguments"))
                            .cloned()
                            .unwrap_or(Value::Null),
                    },
                    None => ClientLine::Drop,
                }
            }
            _ => ClientLine::Forward,
        }
    }

    /// A server line that answers a recorded `tools/list`: the same message with the tool
    /// appended. `None`: forward the line as it is.
    pub fn amend_server_line(&self, line: &[u8]) -> Option<Vec<u8>> {
        // Cheap test first: the hot path is every other message.
        if lock(&self.lists).is_empty() {
            return None;
        }
        let Ok(Value::Object(mut message)) = serde_json::from_slice::<Value>(line) else {
            return None;
        };
        if message.contains_key("method") {
            return None;
        }
        let id = message.get("id").filter(|id| !id.is_null())?;
        if !lock(&self.lists).remove(&id_key(id)) {
            return None;
        }
        let tools = message
            .get_mut("result")
            .and_then(Value::as_object_mut)
            .and_then(|result| result.get_mut("tools"))
            .and_then(Value::as_array_mut)?;
        // A server that lists the name itself keeps its own definition out of the way.
        tools.retain(|tool| tool.get("name").and_then(Value::as_str) != Some(TOOL_NAME));
        tools.push(tool_definition());
        serde_json::to_vec(&Value::Object(message)).ok()
    }

    /// The JSON-RPC response to a tool call, as one line without its newline. Runs the call,
    /// which may wait for the human.
    pub fn answer(&self, id: &Value, arguments: &Value) -> Vec<u8> {
        let outcome = match parse_arguments(arguments) {
            Err(error) => Err(error),
            Ok(call) => {
                if self.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT_CALLS {
                    self.in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok(busy_status(&call))
                } else {
                    let outcome = self.tool.call(call);
                    self.in_flight.fetch_sub(1, Ordering::SeqCst);
                    outcome
                }
            }
        };
        let (text, is_error) = match &outcome {
            Ok(status) => (serde_json::to_string(status), false),
            Err(error) => (serde_json::to_string(error), true),
        };
        let text = text.unwrap_or_else(|_| "{}".to_string());
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "content": [{ "type": "text", "text": text }], "isError": is_error },
        }))
        .unwrap_or_default()
    }
}

/// The answer to a call the relay would not start because [`MAX_IN_FLIGHT_CALLS`] are running.
fn busy_status(call: &AccessCall) -> AccessRequestStatus {
    AccessRequestStatus {
        state: AccessRequestState::Busy,
        rp_id: call.rp_id.clone(),
        action: call.action.clone(),
        expires_in_secs: None,
        retry_after_secs: None,
        message: "Too many access requests are waiting through this MCP server; try again in a \
                  moment."
            .to_string(),
    }
}

// ---------------------------------------------------------------------------------------------
// Line framing.
// ---------------------------------------------------------------------------------------------

/// What [`split_lines`] hands to its callbacks.
enum Piece<'a> {
    /// One complete line (at most [`MAX_INSPECTED_LINE`] bytes, without its newline); `newline`:
    /// it was newline-terminated (the last line of a stream may not be).
    Line { bytes: &'a [u8], newline: bool },
    /// Part of a line too long to inspect, to be forwarded as it arrives.
    Raw(&'a [u8]),
    /// The end of an oversized line (its newline was read).
    RawEnd,
}

/// Cut `reader` into lines, holding at most [`MAX_INSPECTED_LINE`] bytes: a longer line is
/// streamed as [`Piece::Raw`] chunks and a [`Piece::RawEnd`].
fn split_lines<R: BufRead>(
    mut reader: R,
    mut on_piece: impl FnMut(Piece<'_>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut held: Vec<u8> = Vec::new();
    let mut streaming = false;
    loop {
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if chunk.is_empty() {
            if streaming {
                on_piece(Piece::RawEnd)?;
            } else if !held.is_empty() {
                on_piece(Piece::Line {
                    bytes: &held,
                    newline: false,
                })?;
            }
            return Ok(());
        }
        let available = chunk.len();
        match chunk.iter().position(|byte| *byte == b'\n') {
            Some(at) => {
                let head = &chunk[..at];
                if streaming {
                    on_piece(Piece::Raw(head))?;
                    on_piece(Piece::RawEnd)?;
                    streaming = false;
                } else if held.len() + head.len() > MAX_INSPECTED_LINE {
                    on_piece(Piece::Raw(&held))?;
                    on_piece(Piece::Raw(head))?;
                    on_piece(Piece::RawEnd)?;
                    held.clear();
                } else {
                    held.extend_from_slice(head);
                    on_piece(Piece::Line {
                        bytes: &held,
                        newline: true,
                    })?;
                    held.clear();
                }
                reader.consume(at + 1);
            }
            None => {
                if streaming {
                    on_piece(Piece::Raw(chunk))?;
                } else {
                    held.extend_from_slice(chunk);
                    if held.len() > MAX_INSPECTED_LINE {
                        on_piece(Piece::Raw(&held))?;
                        held.clear();
                        streaming = true;
                    }
                }
                reader.consume(available);
            }
        }
    }
}

/// The client's stdout, shared by the server-to-client pump and the tool answers: an answer never
/// lands in the middle of a line being forwarded.
struct ClientOut<W> {
    writer: Mutex<(W, bool)>,
}

impl<W: Write> ClientOut<W> {
    fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new((writer, false)),
        }
    }

    /// Forward a piece of the server's output.
    fn forward(&self, piece: &Piece<'_>) -> std::io::Result<()> {
        let mut guard = lock(&self.writer);
        let (writer, mid_line) = &mut *guard;
        match piece {
            Piece::Line { bytes, newline } => {
                writer.write_all(bytes)?;
                if *newline {
                    writer.write_all(b"\n")?;
                }
            }
            Piece::Raw(bytes) => {
                *mid_line = true;
                writer.write_all(bytes)?;
            }
            Piece::RawEnd => {
                writer.write_all(b"\n")?;
                *mid_line = false;
            }
        }
        writer.flush()
    }

    /// Send a whole message line of the relay's own, once no forwarded line is half written.
    fn send(&self, line: &[u8]) -> std::io::Result<()> {
        loop {
            {
                let mut guard = lock(&self.writer);
                let (writer, mid_line) = &mut *guard;
                if !*mid_line {
                    writer.write_all(line)?;
                    writer.write_all(b"\n")?;
                    return writer.flush();
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The relay's threads. [`Self::finish`] waits for the last of the server's output to reach the
/// client.
pub struct RelayHandle {
    server_pump: JoinHandle<()>,
}

impl RelayHandle {
    /// Wait (briefly) for the server's output to drain: the server has exited, so its end of the
    /// pipe is closed and the pump ends by itself.
    pub fn finish(self) {
        let deadline = Instant::now() + FINISH_WAIT;
        while !self.server_pump.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Start the two pumps between the client (`client_in`, `client_out`) and the server
/// (`server_in`, `server_out`). The client-to-server pump ends at the client's EOF, closing the
/// server's stdin; the server-to-client pump ends at the server's EOF. Neither is joined, but
/// [`RelayHandle::finish`] waits for the second.
pub fn start_relay<CI, CO, SI, SO>(
    tool: Arc<dyn AccessTool>,
    client_in: CI,
    client_out: CO,
    server_in: SI,
    server_out: SO,
) -> RelayHandle
where
    CI: BufRead + Send + 'static,
    CO: Write + Send + 'static,
    SI: Write + Send + 'static,
    SO: BufRead + Send + 'static,
{
    let relay = Arc::new(Relay::new(tool));
    let out = Arc::new(ClientOut::new(client_out));

    let client_pump = {
        let relay = Arc::clone(&relay);
        let out = Arc::clone(&out);
        move || {
            let mut server_in = server_in;
            let _ = split_lines(client_in, |piece| match &piece {
                Piece::Line { bytes, newline } => match relay.classify_client_line(bytes) {
                    ClientLine::Forward => {
                        server_in.write_all(bytes)?;
                        if *newline {
                            server_in.write_all(b"\n")?;
                        }
                        server_in.flush()
                    }
                    ClientLine::Drop => Ok(()),
                    ClientLine::Answer { id, arguments } => {
                        // A call may wait for the human: it must not hold up the client's
                        // other messages.
                        let relay = Arc::clone(&relay);
                        let out = Arc::clone(&out);
                        std::thread::spawn(move || {
                            let _ = out.send(&relay.answer(&id, &arguments));
                        });
                        Ok(())
                    }
                },
                Piece::Raw(bytes) => {
                    server_in.write_all(bytes)?;
                    server_in.flush()
                }
                Piece::RawEnd => {
                    server_in.write_all(b"\n")?;
                    server_in.flush()
                }
            });
            // The client is gone (or the server): dropping `server_in` closes its stdin.
        }
    };
    std::thread::Builder::new()
        .name("passless-mcp-relay-in".to_string())
        .spawn(client_pump)
        .expect("spawn the relay's client pump");

    let server_pump = {
        let relay = Arc::clone(&relay);
        let out = Arc::clone(&out);
        move || {
            let _ = split_lines(server_out, |piece| match &piece {
                Piece::Line { bytes, newline } => match relay.amend_server_line(bytes) {
                    Some(amended) => out.forward(&Piece::Line {
                        bytes: &amended,
                        newline: *newline,
                    }),
                    None => out.forward(&piece),
                },
                _ => out.forward(&piece),
            });
        }
    };
    let server_pump = std::thread::Builder::new()
        .name("passless-mcp-relay-out".to_string())
        .spawn(server_pump)
        .expect("spawn the relay's server pump");
    RelayHandle { server_pump }
}

/// Spawn `command` (an MCP server) with its stdin and stdout piped to a relay that talks to this
/// process's own stdin and stdout; its stderr stays inherited.
pub fn spawn_relayed(
    command: &mut Command,
    tool: Arc<dyn AccessTool>,
) -> std::io::Result<(Child, RelayHandle)> {
    command.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = command.spawn()?;
    let (Some(stdin), Some(stdout)): (Option<ChildStdin>, Option<ChildStdout>) =
        (child.stdin.take(), child.stdout.take())
    else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other("the server's stdio is not piped"));
    };
    let handle = start_relay(
        tool,
        BufReader::new(std::io::stdin()),
        std::io::stdout(),
        stdin,
        BufReader::new(stdout),
    );
    Ok((child, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Cursor, Read};
    use std::os::unix::net::UnixStream;

    /// A tool that records its calls and answers from a script.
    struct FakeTool {
        calls: Mutex<Vec<AccessCall>>,
        reply: Mutex<Box<dyn FnMut(&AccessCall) -> ToolResult + Send>>,
    }

    impl FakeTool {
        fn new(reply: impl FnMut(&AccessCall) -> ToolResult + Send + 'static) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                reply: Mutex::new(Box::new(reply)),
            })
        }

        fn approving() -> Arc<Self> {
            Self::new(|call| Ok(status(AccessRequestState::Approved, call)))
        }
    }

    impl AccessTool for FakeTool {
        fn call(&self, call: AccessCall) -> ToolResult {
            let answer = (lock(&self.reply))(&call);
            lock(&self.calls).push(call);
            answer
        }
    }

    fn status(state: AccessRequestState, call: &AccessCall) -> AccessRequestStatus {
        AccessRequestStatus {
            state,
            rp_id: call.rp_id.clone(),
            action: call.action.clone(),
            expires_in_secs: None,
            retry_after_secs: None,
            message: "m".into(),
        }
    }

    fn relay(tool: Arc<FakeTool>) -> Relay {
        Relay::new(tool)
    }

    fn text_of(response: &[u8]) -> (Value, bool) {
        let value: Value = serde_json::from_slice(response).unwrap();
        let result = &value["result"];
        assert_eq!(result["content"].as_array().unwrap().len(), 1);
        assert_eq!(result["content"][0]["type"], "text");
        let text = result["content"][0]["text"].as_str().unwrap();
        (
            serde_json::from_str(text).unwrap(),
            result["isError"].as_bool().unwrap(),
        )
    }

    #[test]
    fn the_tool_definition_matches_the_adr() {
        let tool = tool_definition();
        assert_eq!(tool["name"], "passless_request_access");
        assert_eq!(tool["inputSchema"]["required"], json!(["rp_id"]));
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        assert_eq!(
            tool["inputSchema"]["properties"]["action"]["enum"],
            json!(["authenticate", "register"])
        );
        assert_eq!(tool["inputSchema"]["properties"]["note"]["maxLength"], 200);
        assert_eq!(
            tool["inputSchema"]["properties"]["wait_seconds"]["maximum"],
            120
        );
        let description = tool["description"].as_str().unwrap();
        assert!(description.contains("NOT shown"), "{description}");
    }

    #[test]
    fn arguments_are_checked_against_the_schema() {
        let ok = parse_arguments(&json!({ "rp_id": "example.org" })).unwrap();
        assert_eq!(
            ok,
            AccessCall {
                rp_id: "example.org".into(),
                action: GrantAction::Authenticate,
                note: None,
                wait_ms: 30_000,
            }
        );
        let full = parse_arguments(&json!({
            "rp_id": "example.org", "action": "register", "note": "why", "wait_seconds": 120
        }))
        .unwrap();
        assert_eq!(full.action, GrantAction::Register);
        assert_eq!(full.note.as_deref(), Some("why"));
        assert_eq!(full.wait_ms, 120_000);
        assert_eq!(
            parse_arguments(&json!({ "rp_id": "a.b", "wait_seconds": 0 }))
                .unwrap()
                .wait_ms,
            0
        );
        for bad in [
            json!({}),
            json!(null),
            json!([]),
            json!("example.org"),
            json!({ "rp_id": "" }),
            json!({ "rp_id": 7 }),
            json!({ "rp_id": "a.b", "action": "sign" }),
            json!({ "rp_id": "a.b", "action": 1 }),
            json!({ "rp_id": "a.b", "note": "x".repeat(201) }),
            json!({ "rp_id": "a.b", "note": 5 }),
            json!({ "rp_id": "a.b", "wait_seconds": 121 }),
            json!({ "rp_id": "a.b", "wait_seconds": -1 }),
            json!({ "rp_id": "a.b", "wait_seconds": 1.5 }),
            json!({ "rp_id": "a.b", "wait_seconds": "30" }),
            json!({ "rp_id": "a.b", "extra": true }),
        ] {
            assert!(parse_arguments(&bad).is_err(), "accepted {bad}");
        }
        // 200 characters, however many bytes they are.
        assert!(parse_arguments(&json!({ "rp_id": "a.b", "note": "é".repeat(200) })).is_ok());
    }

    #[test]
    fn a_tool_call_is_answered_with_the_clients_id_and_never_forwarded() {
        let tool = FakeTool::approving();
        let relay = relay(Arc::clone(&tool));
        for id in [json!(7), json!("abc"), json!(0)] {
            let line = serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": TOOL_NAME, "arguments": { "rp_id": "example.org", "note": "n" } }
            }))
            .unwrap();
            let ClientLine::Answer {
                id: answered,
                arguments,
            } = relay.classify_client_line(&line)
            else {
                panic!("not intercepted");
            };
            assert_eq!(answered, id);
            let response = relay.answer(&answered, &arguments);
            let value: Value = serde_json::from_slice(&response).unwrap();
            assert_eq!(value["jsonrpc"], "2.0");
            assert_eq!(value["id"], id);
            let (status, is_error) = text_of(&response);
            assert!(!is_error);
            assert_eq!(status["state"], "approved");
            assert_eq!(status["rp_id"], "example.org");
        }
        assert_eq!(lock(&tool.calls).len(), 3);
        assert_eq!(lock(&tool.calls)[0].note.as_deref(), Some("n"));

        // Another tool, a notification for ours, other methods: forwarded or dropped.
        let other = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"browser_navigate","arguments":{}}}"#;
        assert_eq!(relay.classify_client_line(other), ClientLine::Forward);
        let notification = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"{TOOL_NAME}"}}}}"#
        );
        assert_eq!(
            relay.classify_client_line(notification.as_bytes()),
            ClientLine::Drop
        );
        for line in [
            &br#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}"#[..],
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            b"not json at all",
            b"",
            b"[1,2,3]",
            b"\"tools/call\"",
        ] {
            assert_eq!(relay.classify_client_line(line), ClientLine::Forward);
        }
    }

    #[test]
    fn every_state_is_not_an_error_and_a_broken_call_is() {
        let relay = relay(FakeTool::new(|call| {
            Ok(status(AccessRequestState::NotEnabled, call))
        }));
        let (status, is_error) = text_of(&relay.answer(&json!(1), &json!({ "rp_id": "a.b" })));
        assert!(!is_error, "{status}");
        assert_eq!(status["state"], "not_enabled");

        // A malformed call: a ProtocolError, isError, and the tool is never asked.
        let tool = FakeTool::approving();
        let strict = Relay::new(tool.clone());
        let (error, is_error) =
            text_of(&strict.answer(&json!(2), &json!({ "rp_id": "a.b", "x": 1 })));
        assert!(is_error);
        assert_eq!(error["code"], "malformed_message", "{error}");
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("unknown argument")
        );
        assert!(lock(&tool.calls).is_empty());

        // A broken link: the tool's own error.
        let broken = Relay::new(FakeTool::new(|_| {
            Err(ProtocolError::new(
                passless_core::agent::protocol::ErrorCode::Internal,
                "the broker link is broken",
                passless_core::agent::protocol::RecommendedAction::Retry,
            ))
        }));
        let (error, is_error) = text_of(&broken.answer(&json!(3), &json!({ "rp_id": "a.b" })));
        assert!(is_error);
        assert_eq!(error["message"], "the broker link is broken");
    }

    #[test]
    fn a_first_page_tools_list_response_gets_the_tool_and_later_pages_do_not() {
        let relay = relay(FakeTool::approving());
        let list = |id: Value, params: Option<Value>| {
            let mut message = json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list" });
            if let Some(params) = params {
                message["params"] = params;
            }
            serde_json::to_vec(&message).unwrap()
        };
        let response = |id: Value| {
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": [{ "name": "browser_navigate" }], "nextCursor": "c1" }
            }))
            .unwrap()
        };
        // Without params, with empty params, with a null cursor: first pages.
        for (n, params) in [None, Some(json!({})), Some(json!({ "cursor": null }))]
            .into_iter()
            .enumerate()
        {
            let id = json!(n + 10);
            assert_eq!(
                relay.classify_client_line(&list(id.clone(), params)),
                ClientLine::Forward
            );
            let amended: Value =
                serde_json::from_slice(&relay.amend_server_line(&response(id)).unwrap()).unwrap();
            let names: Vec<&str> = amended["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tool| tool["name"].as_str().unwrap())
                .collect();
            assert_eq!(names, ["browser_navigate", TOOL_NAME]);
            // Everything else of the response is as the server sent it.
            assert_eq!(amended["result"]["nextCursor"], "c1");
        }
        // A later page (a cursor) is not recorded, so its response is untouched.
        relay.classify_client_line(&list(json!(20), Some(json!({ "cursor": "c1" }))));
        assert!(relay.amend_server_line(&response(json!(20))).is_none());
        // A response nobody asked for, or answered once already, is untouched.
        assert!(relay.amend_server_line(&response(json!(99))).is_none());
        relay.classify_client_line(&list(json!(30), None));
        assert!(relay.amend_server_line(&response(json!(30))).is_some());
        assert!(relay.amend_server_line(&response(json!(30))).is_none());
        // An error response, a server request with the same id and a non-JSON line pass through.
        relay.classify_client_line(&list(json!(40), None));
        let error = br#"{"jsonrpc":"2.0","id":40,"error":{"code":-32601,"message":"no"}}"#;
        assert!(relay.amend_server_line(error).is_none());
        relay.classify_client_line(&list(json!(41), None));
        let request = br#"{"jsonrpc":"2.0","id":41,"method":"ping"}"#;
        assert!(relay.amend_server_line(request).is_none());
        assert!(relay.amend_server_line(b"log line").is_none());
        // String ids stay distinct from number ids.
        relay.classify_client_line(&list(json!("5"), None));
        assert!(relay.amend_server_line(&response(json!(5))).is_none());
        assert!(relay.amend_server_line(&response(json!("5"))).is_some());
    }

    #[test]
    fn a_server_that_lists_the_tool_itself_gets_one_entry() {
        let relay = relay(FakeTool::approving());
        relay.classify_client_line(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let response = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "tools": [{ "name": TOOL_NAME, "description": "the server's" }] }
        }))
        .unwrap();
        let amended: Value =
            serde_json::from_slice(&relay.amend_server_line(&response).unwrap()).unwrap();
        let tools = amended["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_ne!(tools[0]["description"], "the server's");
    }

    /// The pumps over in-memory pipes: what the client sends, what the server receives.
    struct Rig {
        /// The client's side: what it writes, what it reads.
        client_writes: UnixStream,
        client_reads: UnixStream,
        /// The server's side: what it reads, what it writes.
        server_reads: UnixStream,
        server_writes: UnixStream,
        handle: Option<RelayHandle>,
    }

    fn rig(tool: Arc<dyn AccessTool>) -> Rig {
        let (client_writes, relay_client_in) = UnixStream::pair().unwrap();
        let (relay_client_out, client_reads) = UnixStream::pair().unwrap();
        let (relay_server_in, server_reads) = UnixStream::pair().unwrap();
        let (server_writes, relay_server_out) = UnixStream::pair().unwrap();
        let handle = start_relay(
            tool,
            BufReader::new(relay_client_in),
            relay_client_out,
            relay_server_in,
            BufReader::new(relay_server_out),
        );
        Rig {
            client_writes,
            client_reads,
            server_reads,
            server_writes,
            handle: Some(handle),
        }
    }

    /// Read the whole of `reader` (to its EOF).
    fn read_all<R: Read>(mut reader: R) -> Vec<u8> {
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        out
    }

    fn read_line(stream: &mut UnixStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).expect("a line in time");
            if byte[0] == b'\n' {
                return line;
            }
            line.push(byte[0]);
        }
    }

    #[test]
    fn everything_else_is_forwarded_byte_for_byte_in_both_directions() {
        let mut rig = rig(FakeTool::approving());
        // Odd spacing, key order, escapes and non-JSON: nothing is re-encoded.
        let client_lines: [&[u8]; 4] = [
            br#"{  "jsonrpc" : "2.0", "method":"initialize", "id": 1, "params":{"a":"\u00e9"} }"#,
            b"not json",
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            br#"{"method":"tools/call","id":9,"params":{"name":"browser_navigate","arguments":{"url":"https://example.org"}},"jsonrpc":"2.0"}"#,
        ];
        for line in client_lines {
            rig.client_writes.write_all(line).unwrap();
            rig.client_writes.write_all(b"\n").unwrap();
        }
        for line in client_lines {
            assert_eq!(read_line(&mut rig.server_reads), line);
        }
        let server_lines: [&[u8]; 3] = [
            br#"{ "id":1, "jsonrpc":"2.0", "result": {"protocolVersion":"2025-06-18"} }"#,
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}",
            b"\xff\xfe binary",
        ];
        for line in server_lines {
            rig.server_writes.write_all(line).unwrap();
            rig.server_writes.write_all(b"\n").unwrap();
        }
        for line in server_lines {
            assert_eq!(read_line(&mut rig.client_reads), line);
        }
    }

    #[test]
    fn the_tool_is_listed_and_answered_through_the_pumps() {
        let tool = FakeTool::approving();
        let mut rig = rig(tool.clone());
        rig.client_writes
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}\n")
            .unwrap();
        assert_eq!(
            read_line(&mut rig.server_reads),
            br#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
            "the list request reaches the server unchanged"
        );
        rig.server_writes
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[{\"name\":\"browser_navigate\"}]}}\n",
            )
            .unwrap();
        let listed: Value = serde_json::from_slice(&read_line(&mut rig.client_reads)).unwrap();
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["browser_navigate", TOOL_NAME]);

        // The call is answered to the client and never reaches the server; the next line does.
        rig.client_writes
            .write_all(
                format!("{{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{{\"name\":\"{TOOL_NAME}\",\"arguments\":{{\"rp_id\":\"example.org\"}}}}}}\n")
                    .as_bytes(),
            )
            .unwrap();
        rig.client_writes
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"ping\"}\n")
            .unwrap();
        assert_eq!(
            read_line(&mut rig.server_reads),
            br#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#
        );
        let (status, is_error) = text_of(&read_line(&mut rig.client_reads));
        assert!(!is_error);
        assert_eq!(status["state"], "approved");
        assert_eq!(lock(&tool.calls).len(), 1);
    }

    #[test]
    fn a_waiting_call_does_not_hold_up_other_messages() {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let wait = Mutex::new(wait);
        let tool = FakeTool::new(move |call| {
            let _ = lock(&wait).recv_timeout(Duration::from_secs(10));
            Ok(status(AccessRequestState::Approved, call))
        });
        let mut rig = rig(tool);
        rig.client_writes
            .write_all(
                format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"{TOOL_NAME}\",\"arguments\":{{\"rp_id\":\"example.org\"}}}}}}\n")
                    .as_bytes(),
            )
            .unwrap();
        rig.client_writes
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n")
            .unwrap();
        // The ping goes through while the call waits for the human.
        assert_eq!(
            read_line(&mut rig.server_reads),
            br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#
        );
        release.send(()).unwrap();
        let (status, _) = text_of(&read_line(&mut rig.client_reads));
        assert_eq!(status["state"], "approved");
    }

    #[test]
    fn at_most_four_calls_wait_at_once_and_the_fifth_is_busy() {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let wait = Arc::new(Mutex::new(wait));
        let tool = FakeTool::new({
            let wait = Arc::clone(&wait);
            move |call| {
                let _ = lock(&wait).recv_timeout(Duration::from_secs(10));
                Ok(status(AccessRequestState::Approved, call))
            }
        });
        let relay = Arc::new(Relay::new(tool));
        let workers: Vec<_> = (0..MAX_IN_FLIGHT_CALLS)
            .map(|n| {
                let relay = Arc::clone(&relay);
                std::thread::spawn(move || {
                    relay.answer(&json!(n), &json!({ "rp_id": "example.org" }))
                })
            })
            .collect();
        while relay.in_flight.load(Ordering::SeqCst) < MAX_IN_FLIGHT_CALLS {
            std::thread::sleep(Duration::from_millis(5));
        }
        let (busy, is_error) =
            text_of(&relay.answer(&json!(99), &json!({ "rp_id": "example.org" })));
        assert!(!is_error);
        assert_eq!(busy["state"], "busy");
        for _ in 0..MAX_IN_FLIGHT_CALLS {
            release.send(()).unwrap();
        }
        for worker in workers {
            assert_eq!(text_of(&worker.join().unwrap()).0["state"], "approved");
        }
        assert_eq!(relay.in_flight.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_clients_eof_closes_the_servers_stdin() {
        let mut rig = rig(FakeTool::approving());
        rig.client_writes
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
            .unwrap();
        rig.client_writes
            .shutdown(std::net::Shutdown::Write)
            .unwrap();
        assert_eq!(
            read_all(&mut rig.server_reads),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
            "the server reads the line, then EOF"
        );
        // And the server's exit ends the relay's output.
        rig.server_writes.write_all(b"last\n").unwrap();
        drop(rig.server_writes);
        rig.handle.take().unwrap().finish();
        assert_eq!(read_all(&mut rig.client_reads), b"last\n");
    }

    #[test]
    fn a_line_without_a_final_newline_is_forwarded_as_it_is() {
        let mut got = Vec::new();
        split_lines(Cursor::new(b"a\nb".to_vec()), |piece| {
            match piece {
                Piece::Line { bytes, newline } => {
                    got.extend_from_slice(bytes);
                    if newline {
                        got.push(b'\n');
                    }
                }
                _ => panic!("no raw piece"),
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(got, b"a\nb");
    }

    /// A line over the limit is streamed untouched, a line right at the limit is inspected, and
    /// the lines around them are unaffected.
    #[test]
    fn oversized_lines_are_forwarded_unchanged_and_never_inspected() {
        let big = vec![b'x'; MAX_INSPECTED_LINE + 1000];
        let at_limit = vec![b'y'; MAX_INSPECTED_LINE];
        let mut input = Vec::new();
        input.extend_from_slice(b"before\n");
        input.extend_from_slice(&big);
        input.push(b'\n');
        input.extend_from_slice(&at_limit);
        input.push(b'\n');
        input.extend_from_slice(b"after\n");

        let mut forwarded = Vec::new();
        let mut inspected = Vec::new();
        // A small buffer makes the line cross many `fill_buf` calls.
        split_lines(
            BufReader::with_capacity(8192, Cursor::new(input.clone())),
            |piece| {
                match piece {
                    Piece::Line { bytes, newline } => {
                        inspected.push(bytes.len());
                        forwarded.extend_from_slice(bytes);
                        if newline {
                            forwarded.push(b'\n');
                        }
                    }
                    Piece::Raw(bytes) => forwarded.extend_from_slice(bytes),
                    Piece::RawEnd => forwarded.push(b'\n'),
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(forwarded, input, "the stream is reproduced exactly");
        assert_eq!(
            inspected,
            [6, MAX_INSPECTED_LINE, 5],
            "the big line is not inspected"
        );
    }

    /// The same through the pumps: an oversized server line reaches the client whole, and a tool
    /// answer written meanwhile never lands inside it.
    #[test]
    fn an_answer_never_lands_inside_a_line_being_forwarded() {
        let out = ClientOut::new(Vec::new());
        out.forward(&Piece::Raw(b"abc")).unwrap();
        let out = Arc::new(out);
        let sender = {
            let out = Arc::clone(&out);
            std::thread::spawn(move || out.send(b"ANSWER").unwrap())
        };
        std::thread::sleep(Duration::from_millis(50));
        out.forward(&Piece::Raw(b"def")).unwrap();
        out.forward(&Piece::RawEnd).unwrap();
        sender.join().unwrap();
        let written = lock(&out.writer).0.clone();
        assert_eq!(written, b"abcdef\nANSWER\n");
    }
}
