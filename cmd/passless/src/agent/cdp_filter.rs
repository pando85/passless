//! The extension filter of pipe-mode `browser-control` (ADR 0014 sections 4.3 and 11, review M3).
//!
//! In pipe mode every CDP command of the agent goes through the daemon, so the daemon keeps the
//! agent away from the Passless extension: the extension's service worker holds the daemon bearer
//! and reports request origins, and a CDP session on it could read the bearer, forge request
//! details or detach the WebAuthn proxy. The filter
//!
//! - denies the `Extensions` domain, `Target.exposeDevToolsProtocol` (it would hand page script an
//!   unfiltered CDP channel to the browser), `Target.sendMessageToTarget` and
//!   `Target.attachToBrowserTarget` (the agent already holds the browser session), and the
//!   `ServiceWorker` commands that inspect or stop workers by version (`inspectWorker`,
//!   `stopWorker`, `stopAllWorkers`), which cannot be attributed to a worker without tracking
//!   every registration;
//! - allows only flat sessions: `Target.attachToTarget` and `Target.setAutoAttach` must say
//!   `flatten: true`, so every session's traffic is a top-level message the filter sees (a
//!   non-flat session would tunnel commands through a JSON string, review H1);
//! - denies a command whose `targetId` names an extension target, or whose session is on one. The
//!   daemon asks the browser with its own `Target.getTargetInfo` before it forwards a command that
//!   names a target, or that runs on a session (the session's target is looked up, so a target
//!   that turned into an extension page since it was attached is caught, review H2). A session the
//!   filter never saw being created is refused;
//! - denies a command whose parameters name an extension (`chrome-extension:`, the extension ID)
//!   or a browser-internal page (`chrome:`, `chrome-untrusted:`, `chrome-search:`, `devtools:`,
//!   `chrome-devtools:`, and `about:` except `about:blank` and `about:srcdoc`, since
//!   `about:inspect` is `chrome://inspect`). Strings are matched after the normalization a URL
//!   parser applies (tabs and newlines dropped, `\uXXXX`/`\xHH` and percent escapes decoded once,
//!   lowercase), and a string that is itself JSON is searched too;
//! - hides extension targets from the agent: every response's `targetInfos` lose them, a
//!   `targetInfo` of one becomes an error, and target events about them are dropped. When a target
//!   is found to be an extension target, every session on it is refused and detached by the
//!   daemon (resuming the target first if an auto-attach left it waiting for a debugger).
//!
//! The filter never forwards an agent command with an ID in the daemon's range (from
//! [`AGENT_ID_LIMIT`]), swallows the responses to its own commands and drops a browser message it
//! cannot parse. The caller forwards the request it checked, re-serialized, never the raw text.
//!
//! Port mode exposes Chromium's DevTools listener directly and is not filtered (ADR 0014
//! section 15).

use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::{Value, json};

/// Agent request IDs must stay below this. The daemon's own CDP commands use IDs from here up
/// (`START_URL_CDP_ID` and the filter's lookups).
pub const AGENT_ID_LIMIT: u64 = 2_000_000_000;
/// The filter's own commands (target lookups, detaches) use IDs in this range. CDP IDs are 32-bit
/// signed integers in Chromium.
const INTERNAL_ID_BASE: u64 = 2_100_000_000;
const INTERNAL_ID_MAX: u64 = i32::MAX as u64;
/// How many extension targets and refused sessions the filter remembers. A session that was
/// detached is dead in the browser, so forgetting the oldest one does not reopen it.
const MAX_TRACKED: usize = 256;
/// How many live sessions (session to target) the filter tracks. A command on a session it no
/// longer tracks is refused, so the bound fails closed.
const MAX_SESSIONS: usize = 4096;
/// How many forwarded `Target.attachToTarget` requests may await their response. Beyond it a new
/// attach is refused (an unmapped session would be refused anyway).
const MAX_PENDING_ATTACHES: usize = 64;
/// How deep a JSON document inside a string is searched.
const MAX_NESTED_JSON_DEPTH: usize = 4;

const DENIED_METHODS: &[&str] = &[
    "Target.exposeDevToolsProtocol",
    "Target.sendMessageToTarget",
    "Target.attachToBrowserTarget",
    "ServiceWorker.inspectWorker",
    "ServiceWorker.stopWorker",
    "ServiceWorker.stopAllWorkers",
];

/// Commands that open sessions: allowed only with `flatten: true`.
const FLAT_ONLY_METHODS: &[&str] = &["Target.attachToTarget", "Target.setAutoAttach"];

/// URL schemes of browser-internal pages (from which the extension could be inspected,
/// disabled or driven).
const INTERNAL_SCHEMES: &[&str] = &[
    "chrome:",
    "chrome-untrusted:",
    "chrome-search:",
    "chrome-devtools:",
    "devtools:",
];

/// What to do with an agent's CDP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestVerdict {
    Forward,
    /// The request names targets (directly, or through its session) that must be looked up
    /// first ([`ExtensionCdpFilter::lookup_command`], [`ExtensionCdpFilter::lookup_result`]).
    LookupTargets(Vec<String>),
    Deny(String),
}

/// What to do with a message from the browser. Daemon commands it gave rise to are collected
/// with [`ExtensionCdpFilter::take_commands`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Deliver(String),
    /// Hide the message from the agent.
    Drop,
}

#[derive(Debug, Default)]
struct BoundedSet {
    order: VecDeque<String>,
    members: HashSet<String>,
}

impl BoundedSet {
    fn insert(&mut self, value: &str) {
        if self.members.contains(value) {
            return;
        }
        if self.order.len() >= MAX_TRACKED
            && let Some(oldest) = self.order.pop_front()
        {
            self.members.remove(&oldest);
        }
        self.order.push_back(value.to_string());
        self.members.insert(value.to_string());
    }

    fn contains(&self, value: &str) -> bool {
        self.members.contains(value)
    }
}

/// A live session: its target and the session it was attached through (`None`: the root).
#[derive(Debug, Clone)]
struct SessionInfo {
    target: String,
    parent: Option<String>,
}

/// Per-lease state of the filter (see the module documentation).
#[derive(Debug)]
pub struct ExtensionCdpFilter {
    /// The extension ID, lowercase.
    extension_id: String,
    /// Targets known to be extension targets.
    targets: BoundedSet,
    /// Sessions refused (on an extension target).
    denied_sessions: BoundedSet,
    /// Live sessions, oldest first for eviction.
    sessions: HashMap<String, SessionInfo>,
    session_order: VecDeque<String>,
    /// Forwarded `Target.attachToTarget` requests: (id, target, the session it was sent on).
    pending_attaches: VecDeque<(u64, String, Option<String>)>,
    /// Daemon commands to send to the browser (detaches).
    outbox: Vec<String>,
    next_internal: u64,
}

impl ExtensionCdpFilter {
    pub fn new(extension_id: &str) -> Self {
        Self {
            extension_id: extension_id.to_ascii_lowercase(),
            targets: BoundedSet::default(),
            denied_sessions: BoundedSet::default(),
            sessions: HashMap::new(),
            session_order: VecDeque::new(),
            pending_attaches: VecDeque::new(),
            outbox: Vec::new(),
            next_internal: INTERNAL_ID_BASE,
        }
    }

    /// Check an agent request (already validated as a CDP request object).
    pub fn check_request(&self, request: &Value) -> RequestVerdict {
        let deny = |reason: &str| RequestVerdict::Deny(reason.to_string());
        let Some(object) = request.as_object() else {
            return deny("the request is not a JSON object");
        };
        match object.get("id").and_then(Value::as_u64) {
            Some(id) if id < AGENT_ID_LIMIT => {}
            _ => {
                return deny(
                    "the request ID must be an integer below 2000000000 (higher ones are the \
                     daemon's)",
                );
            }
        }
        let method = object.get("method").and_then(Value::as_str).unwrap_or("");
        if method.starts_with("Extensions.") || DENIED_METHODS.contains(&method) {
            return RequestVerdict::Deny(format!(
                "{method} is not available through browser-control"
            ));
        }
        let params = object.get("params").unwrap_or(&Value::Null);
        if FLAT_ONLY_METHODS.contains(&method) && params.get("flatten") != Some(&Value::Bool(true))
        {
            return RequestVerdict::Deny(format!(
                "{method} is available through browser-control only with flatten: true"
            ));
        }
        if method == "Target.attachToTarget" && self.pending_attaches.len() >= MAX_PENDING_ATTACHES
        {
            return deny("too many attaches await their response");
        }

        let mut lookups = Vec::new();
        if let Some(session) = object.get("sessionId") {
            let Some(session) = session.as_str() else {
                return deny("the session ID is not a string");
            };
            if self.denied_sessions.contains(session) {
                return deny("the session belongs to the Passless extension");
            }
            let Some(info) = self.sessions.get(session) else {
                return deny("the session is not one browser-control attached");
            };
            if self.targets.contains(&info.target) {
                return deny("the session belongs to the Passless extension");
            }
            lookups.push(info.target.clone());
        }
        if params
            .get("sessionId")
            .and_then(Value::as_str)
            .is_some_and(|session| self.denied_sessions.contains(session))
        {
            return deny("the session belongs to the Passless extension");
        }
        if let Some(reason) = self.forbidden_reference(params) {
            return deny(reason);
        }
        match params.get("targetId").and_then(Value::as_str) {
            Some(target) if self.targets.contains(target) => {
                return deny("the target is the Passless extension");
            }
            Some(target) if !lookups.iter().any(|known| known == target) => {
                lookups.push(target.to_string());
            }
            _ => {}
        }
        if lookups.is_empty() {
            RequestVerdict::Forward
        } else {
            RequestVerdict::LookupTargets(lookups)
        }
    }

    /// Remember a forwarded agent request whose response opens a session.
    pub fn note_forwarded(&mut self, request: &Value) {
        if request.get("method").and_then(Value::as_str) != Some("Target.attachToTarget") {
            return;
        }
        let (Some(id), Some(target)) = (
            request.get("id").and_then(Value::as_u64),
            request.pointer("/params/targetId").and_then(Value::as_str),
        ) else {
            return;
        };
        let parent = request
            .get("sessionId")
            .and_then(Value::as_str)
            .map(str::to_string);
        if self.pending_attaches.len() < MAX_PENDING_ATTACHES {
            self.pending_attaches
                .push_back((id, target.to_string(), parent));
        }
    }

    /// The daemon-issued lookup of `target_id`: its request ID and its frame.
    pub fn lookup_command(&mut self, target_id: &str) -> (u64, String) {
        self.internal_command(
            "Target.getTargetInfo",
            json!({ "targetId": target_id }),
            None,
        )
    }

    /// Record the lookup's response. True when `target_id` is an extension target; its sessions
    /// are then refused and detached ([`Self::take_commands`]).
    pub fn lookup_result(&mut self, target_id: &str, response: &Value) -> bool {
        let extension = response
            .pointer("/result/targetInfo")
            .is_some_and(|info| self.is_extension_target(info));
        if extension {
            self.mark_extension_target(target_id);
        }
        extension
    }

    /// The daemon commands the filter decided on since the last call (detaches), to be written
    /// to the browser.
    pub fn take_commands(&mut self) -> Vec<String> {
        std::mem::take(&mut self.outbox)
    }

    /// The ID of a response to one of the filter's own commands.
    pub fn is_internal_id(id: u64) -> bool {
        id >= INTERNAL_ID_BASE
    }

    /// Filter a message from the browser before the agent sees it.
    pub fn inbound(&mut self, raw: &str) -> Inbound {
        let Ok(mut message) = serde_json::from_str::<Value>(raw) else {
            // Never relay what the filter could not inspect.
            return Inbound::Drop;
        };
        if let Some(id) = message.get("id").and_then(Value::as_u64) {
            if Self::is_internal_id(id) {
                return Inbound::Drop;
            }
            self.note_attach_response(id, &message);
            return if self.rewrite_response(&mut message) {
                Inbound::Deliver(message.to_string())
            } else {
                Inbound::Deliver(raw.to_string())
            };
        }
        if message
            .get("sessionId")
            .and_then(Value::as_str)
            .is_some_and(|session| self.denied_sessions.contains(session))
        {
            return Inbound::Drop;
        }
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let target_info = params.get("targetInfo");
        let info_target = target_info
            .and_then(|info| info.get("targetId"))
            .and_then(Value::as_str);
        match method.as_str() {
            // Non-flat sessions are refused, so nothing legitimate arrives this way.
            "Target.receivedMessageFromTarget" => return Inbound::Drop,
            "Target.attachedToTarget" => {
                let session = params.get("sessionId").and_then(Value::as_str);
                let extension = target_info.is_some_and(|info| self.is_extension_target(info))
                    || info_target.is_some_and(|target| self.targets.contains(target));
                // Resume first, then detach (the detach is queued when the session is marked).
                if extension
                    && let Some(session) = session
                    && params.get("waitingForDebugger") == Some(&Value::Bool(true))
                {
                    let resume = self
                        .internal_command(
                            "Runtime.runIfWaitingForDebugger",
                            json!({}),
                            Some(session),
                        )
                        .1;
                    self.outbox.push(resume);
                }
                if let (Some(session), Some(target)) = (session, info_target) {
                    let parent = message.get("sessionId").and_then(Value::as_str);
                    self.track_session(session, target, parent);
                }
                if extension {
                    match (info_target, session) {
                        (Some(target), _) => self.mark_extension_target(target),
                        (None, Some(session)) => {
                            let parent = message.get("sessionId").and_then(Value::as_str);
                            self.deny_session(session, parent);
                        }
                        (None, None) => {}
                    }
                    return Inbound::Drop;
                }
            }
            "Target.targetCreated" | "Target.targetInfoChanged" => {
                if let Some(info) = target_info
                    && self.is_extension_target(info)
                {
                    if let Some(target) = info_target {
                        self.mark_extension_target(target);
                    }
                    return Inbound::Drop;
                }
            }
            "Target.targetDestroyed" | "Target.targetCrashed" => {
                if let Some(target) = params.get("targetId").and_then(Value::as_str) {
                    self.forget_target_sessions(target);
                    if self.targets.contains(target) {
                        return Inbound::Drop;
                    }
                }
            }
            "Target.detachedFromTarget" => {
                let session = params.get("sessionId").and_then(Value::as_str);
                let target = params.get("targetId").and_then(Value::as_str);
                if let Some(session) = session {
                    self.forget_session(session);
                }
                if session.is_some_and(|s| self.denied_sessions.contains(s))
                    || target.is_some_and(|t| self.targets.contains(t))
                {
                    return Inbound::Drop;
                }
            }
            _ => {}
        }
        // Any other event that names the extension (service worker registrations, for example).
        if mentions(&params, &self.extension_id) {
            return Inbound::Drop;
        }
        Inbound::Deliver(raw.to_string())
    }

    /// `target` is an extension target: remember it, and refuse and detach every session on it.
    fn mark_extension_target(&mut self, target: &str) {
        self.remember_extension_target(target);
        let sessions: Vec<(String, Option<String>)> = self
            .sessions
            .iter()
            .filter(|(session, info)| {
                info.target == target && !self.denied_sessions.contains(session)
            })
            .map(|(session, info)| (session.clone(), info.parent.clone()))
            .collect();
        for (session, parent) in sessions {
            self.deny_session(&session, parent.as_deref());
        }
    }

    /// Remember `target` as an extension target. Logged at debug level (the target ID is not a
    /// secret: the filter refuses every command that names it, and the E2E harness reads it here
    /// to attack it).
    fn remember_extension_target(&mut self, target: &str) {
        if !self.targets.contains(target) {
            log::debug!("cdp filter: hid extension target {target}");
        }
        self.targets.insert(target);
    }

    /// Refuse `session` from now on and detach it (on its parent session, or the root).
    fn deny_session(&mut self, session: &str, parent: Option<&str>) {
        self.denied_sessions.insert(session);
        let detach = self
            .internal_command(
                "Target.detachFromTarget",
                json!({ "sessionId": session }),
                parent,
            )
            .1;
        self.outbox.push(detach);
    }

    fn track_session(&mut self, session: &str, target: &str, parent: Option<&str>) {
        if !self.sessions.contains_key(session) {
            if self.session_order.len() >= MAX_SESSIONS
                && let Some(oldest) = self.session_order.pop_front()
            {
                self.sessions.remove(&oldest);
            }
            self.session_order.push_back(session.to_string());
        }
        self.sessions.insert(
            session.to_string(),
            SessionInfo {
                target: target.to_string(),
                parent: parent.map(str::to_string),
            },
        );
        if self.targets.contains(target) {
            self.mark_extension_target(target);
        }
    }

    fn forget_session(&mut self, session: &str) {
        if self.sessions.remove(session).is_some() {
            self.session_order.retain(|known| known != session);
        }
    }

    fn forget_target_sessions(&mut self, target: &str) {
        let gone: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, info)| info.target == target)
            .map(|(session, _)| session.clone())
            .collect();
        for session in gone {
            self.forget_session(&session);
        }
    }

    /// Map the session a forwarded `Target.attachToTarget` opened to its target.
    fn note_attach_response(&mut self, id: u64, message: &Value) {
        let Some(index) = self
            .pending_attaches
            .iter()
            .position(|(pending, _, _)| *pending == id)
        else {
            return;
        };
        let Some((_, target, parent)) = self.pending_attaches.remove(index) else {
            return;
        };
        if let Some(session) = message.pointer("/result/sessionId").and_then(Value::as_str) {
            self.track_session(session, &target, parent.as_deref());
        }
    }

    /// Hide extension targets in any response: `targetInfos` lose them and a `targetInfo` of one
    /// becomes an error. True when the message changed. Applied to every response, whatever
    /// command it answers, so no bookkeeping can be outrun.
    fn rewrite_response(&mut self, message: &mut Value) -> bool {
        let mut hidden = Vec::new();
        let mut changed = false;
        if let Some(infos) = message
            .pointer_mut("/result/targetInfos")
            .and_then(Value::as_array_mut)
        {
            let extension_id = self.extension_id.clone();
            infos.retain(|info| {
                let extension = target_info_is_extension(info, &extension_id);
                if extension && let Some(target) = info.get("targetId").and_then(Value::as_str) {
                    hidden.push(target.to_string());
                }
                if extension {
                    changed = true;
                }
                !extension
            });
        }
        if let Some(info) = message.pointer("/result/targetInfo")
            && self.is_extension_target(info)
        {
            if let Some(target) = info.get("targetId").and_then(Value::as_str) {
                hidden.push(target.to_string());
            }
            let id = message.get("id").cloned().unwrap_or(Value::Null);
            *message = json!({
                "id": id,
                "error": {"code": -32000, "message": "No target with given id found"},
            });
            changed = true;
        }
        for target in &hidden {
            self.mark_extension_target(target);
        }
        changed
    }

    fn internal_command(
        &mut self,
        method: &str,
        params: Value,
        session: Option<&str>,
    ) -> (u64, String) {
        let id = self.next_internal;
        self.next_internal = if id >= INTERNAL_ID_MAX {
            INTERNAL_ID_BASE
        } else {
            id + 1
        };
        let mut command = json!({ "id": id, "method": method, "params": params });
        if let (Some(session), Some(object)) = (session, command.as_object_mut()) {
            object.insert("sessionId".to_string(), Value::String(session.to_string()));
        }
        (id, command.to_string())
    }

    fn is_extension_target(&self, info: &Value) -> bool {
        target_info_is_extension(info, &self.extension_id)
    }

    /// Why `params` may not be forwarded, if a string in it names an extension or a
    /// browser-internal page.
    fn forbidden_reference(&self, params: &Value) -> Option<&'static str> {
        let mut found = None;
        visit_strings(params, 0, &mut |text| {
            if found.is_some() {
                return;
            }
            let text = normalize(text);
            if text.contains(&self.extension_id) || text.contains("chrome-extension:") {
                found = Some("the request names an extension");
            } else if INTERNAL_SCHEMES
                .iter()
                .any(|scheme| names_scheme(&text, scheme))
                || names_internal_about_page(&text)
            {
                found = Some("the request names a browser-internal page");
            }
        });
        found
    }
}

fn target_info_is_extension(info: &Value, extension_id: &str) -> bool {
    info.get("url")
        .and_then(Value::as_str)
        .is_some_and(|url| normalize(url).contains(extension_id))
}

/// Every string in `value`, object keys included. A string that is itself a JSON object or
/// array is parsed and searched as well, up to [`MAX_NESTED_JSON_DEPTH`] levels.
fn visit_strings(value: &Value, depth: usize, visit: &mut dyn FnMut(&str)) {
    match value {
        Value::String(text) => {
            visit(text);
            visit_nested_json(text, depth, visit);
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| visit_strings(item, depth, visit)),
        Value::Object(map) => {
            for (key, item) in map {
                visit(key);
                visit_nested_json(key, depth, visit);
                visit_strings(item, depth, visit);
            }
        }
        _ => {}
    }
}

fn visit_nested_json(text: &str, depth: usize, visit: &mut dyn FnMut(&str)) {
    if depth >= MAX_NESTED_JSON_DEPTH {
        return;
    }
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"')) {
        return;
    }
    if let Ok(nested) = serde_json::from_str::<Value>(trimmed) {
        visit_strings(&nested, depth + 1, visit);
    }
}

fn mentions(value: &Value, needle: &str) -> bool {
    let mut found = false;
    visit_strings(value, 0, &mut |text| {
        found = found || normalize(text).contains(needle);
    });
    found
}

/// `scheme` used as a URL scheme somewhere in `text` (already normalized): followed by a slash,
/// a backslash or a letter (`chrome://extensions`, `chrome:extensions`).
fn names_scheme(text: &str, scheme: &str) -> bool {
    text.match_indices(scheme).any(|(at, _)| {
        text.get(at + scheme.len()..)
            .and_then(|rest| rest.chars().next())
            .is_some_and(|next| next == '/' || next == '\\' || next.is_ascii_alphabetic())
    })
}

/// An `about:` URL other than `about:blank` and `about:srcdoc` (Chromium maps the others, such as
/// `about:inspect` and `about:extensions`, to `chrome://` pages).
fn names_internal_about_page(text: &str) -> bool {
    text.match_indices("about:").any(|(at, scheme)| {
        let rest = text.get(at + scheme.len()..).unwrap_or("");
        let rest = rest.trim_start_matches(['/', '\\']);
        let page: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        !page.is_empty() && page != "blank" && page != "srcdoc"
    })
}

/// What a URL parser and a script would do before a scheme or a host is compared: ASCII tabs and
/// newlines are dropped, `\uXXXX` and `\xHH` escapes and then percent escapes are decoded once,
/// and the result is lowercased.
fn normalize(text: &str) -> String {
    let stripped: String = text
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let unescaped = decode_backslash_escapes(&stripped);
    let bytes = unescaped.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let escaped = (byte == b'%')
            .then(|| {
                let high = char::from(*bytes.get(index + 1)?).to_digit(16)?;
                let low = char::from(*bytes.get(index + 2)?).to_digit(16)?;
                u8::try_from(high * 16 + low).ok()
            })
            .flatten();
        match escaped {
            Some(value) => {
                decoded.push(value);
                index += 3;
            }
            None => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).to_ascii_lowercase()
}

/// Decode `\uXXXX` and `\xHH` escapes once (JSON and JavaScript spell characters this way inside
/// strings); anything else is kept as it is.
fn decode_backslash_escapes(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while let Some(&c) = chars.get(index) {
        if c == '\\' {
            let digits = match chars.get(index + 1) {
                Some('u') => 4,
                Some('x') => 2,
                _ => 0,
            };
            if digits > 0 {
                let hex: Option<String> = (0..digits)
                    .map(|offset| chars.get(index + 2 + offset).copied())
                    .collect();
                if let Some(decoded) = hex
                    .filter(|hex| hex.chars().all(|h| h.is_ascii_hexdigit()))
                    .and_then(|hex| u32::from_str_radix(&hex, 16).ok())
                    .and_then(char::from_u32)
                {
                    out.push(decoded);
                    index += 2 + digits;
                    continue;
                }
            }
        }
        out.push(c);
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "lfbahamapdlbimlffmhiomfdemnjhjkc";
    const WORKER_URL: &str = "chrome-extension://lfbahamapdlbimlffmhiomfdemnjhjkc/worker.js";

    fn filter() -> ExtensionCdpFilter {
        ExtensionCdpFilter::new(ID)
    }

    fn denied(filter: &ExtensionCdpFilter, request: Value) -> bool {
        matches!(filter.check_request(&request), RequestVerdict::Deny(_))
    }

    fn worker_info(target: &str) -> Value {
        json!({"targetId": target, "type": "service_worker", "title": "", "url": WORKER_URL,
               "attached": false, "canAccessOpener": false})
    }

    fn page_info(target: &str) -> Value {
        json!({"targetId": target, "type": "page", "title": "", "url": "https://rp.test/",
               "attached": false, "canAccessOpener": false})
    }

    fn parse(message: &str) -> Value {
        serde_json::from_str(message).unwrap()
    }

    /// A filter that saw page target `P` attached as flat session `S` (an auto-attach).
    fn filter_with_page_session() -> ExtensionCdpFilter {
        let mut f = filter();
        let attached = json!({"method": "Target.attachedToTarget", "params": {
            "sessionId": "S", "targetInfo": page_info("P"), "waitingForDebugger": false}});
        assert!(matches!(
            f.inbound(&attached.to_string()),
            Inbound::Deliver(_)
        ));
        f
    }

    #[test]
    fn ordinary_automation_is_forwarded() {
        let f = filter();
        for request in [
            json!({"id": 1, "method": "Page.navigate", "params": {"url": "https://rp.test/"}}),
            json!({"id": 3, "method": "Target.setAutoAttach",
                   "params": {"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}}),
            json!({"id": 4, "method": "Target.setDiscoverTargets", "params": {"discover": true}}),
            json!({"id": 5, "method": "Target.getTargets"}),
            json!({"id": 6, "method": "Target.createTarget", "params": {"url": "about:blank"}}),
            json!({"id": 7, "method": "Runtime.evaluate",
                   "params": {"expression": "navigator.userAgent.includes('Chrome')"}}),
            json!({"id": 8, "method": "Runtime.evaluate",
                   "params": {"expression": "document.write('about: us'); location = 'about:srcdoc'"}}),
        ] {
            assert_eq!(
                f.check_request(&request),
                RequestVerdict::Forward,
                "{request}"
            );
        }
        // A command on a session is forwarded after its target was looked up.
        let f = filter_with_page_session();
        assert_eq!(
            f.check_request(&json!({"id": 2, "method": "Runtime.evaluate",
                                    "params": {"expression": "1 + 1"}, "sessionId": "S"})),
            RequestVerdict::LookupTargets(vec!["P".to_string()])
        );
    }

    #[test]
    fn a_target_command_is_looked_up_unless_the_target_is_known() {
        let mut f = filter();
        let attach = json!({"id": 1, "method": "Target.attachToTarget",
                            "params": {"targetId": "W", "flatten": true}});
        assert_eq!(
            f.check_request(&attach),
            RequestVerdict::LookupTargets(vec!["W".to_string()])
        );
        let (id, command) = f.lookup_command("W");
        assert!(ExtensionCdpFilter::is_internal_id(id));
        let command = parse(&command);
        assert_eq!(command["method"], "Target.getTargetInfo");
        assert_eq!(command["params"]["targetId"], "W");
        assert!(f.lookup_result(
            "W",
            &json!({"id": id, "result": {"targetInfo": worker_info("W")}})
        ));
        // Known now: every targeted command on it is denied without another lookup.
        for method in [
            "Target.attachToTarget",
            "Target.closeTarget",
            "Target.activateTarget",
            "Target.autoAttachRelated",
            "Target.openDevTools",
            "Target.getTargetInfo",
        ] {
            assert!(
                denied(
                    &f,
                    json!({"id": 2, "method": method, "params": {"targetId": "W", "flatten": true}})
                ),
                "{method}"
            );
        }
        // A page target passes its lookup.
        let (id, _) = f.lookup_command("P");
        assert!(!f.lookup_result(
            "P",
            &json!({"id": id, "result": {"targetInfo": page_info("P")}})
        ));
        // An unknown target (an error response) is not an extension target: the browser answers.
        assert!(!f.lookup_result("X", &json!({"id": id, "error": {"code": -32602}})));
    }

    #[test]
    fn extension_domains_tunnels_and_worker_controls_are_denied() {
        let f = filter();
        for method in [
            "Extensions.loadUnpacked",
            "Extensions.getStorageItems",
            "Extensions.uninstall",
            "Target.exposeDevToolsProtocol",
            "Target.sendMessageToTarget",
            "Target.attachToBrowserTarget",
            "ServiceWorker.inspectWorker",
            "ServiceWorker.stopWorker",
            "ServiceWorker.stopAllWorkers",
        ] {
            assert!(denied(&f, json!({"id": 1, "method": method})), "{method}");
        }
    }

    #[test]
    fn non_flat_sessions_are_refused() {
        // Review H1: `flatten` defaults to false, which gives a session whose traffic is tunnelled
        // through `Target.sendMessageToTarget` strings.
        let f = filter();
        for request in [
            json!({"id": 1, "method": "Target.attachToTarget", "params": {"targetId": "P"}}),
            json!({"id": 1, "method": "Target.attachToTarget",
                   "params": {"targetId": "P", "flatten": false}}),
            json!({"id": 1, "method": "Target.attachToTarget",
                   "params": {"targetId": "P", "flatten": "true"}}),
            json!({"id": 1, "method": "Target.setAutoAttach",
                   "params": {"autoAttach": true, "waitForDebuggerOnStart": false}}),
        ] {
            assert!(denied(&f, request.clone()), "{request}");
        }
    }

    #[test]
    fn the_review_tunnel_payload_is_denied() {
        // Review H1: the non-flat session's command, with the URL spelled in `\u` escapes inside
        // the tunnelled JSON string. The method is refused outright, and its nested JSON would be
        // caught as well.
        let f = filter_with_page_session();
        let raw = r#"{"id":5,"method":"Target.sendMessageToTarget","params":{"sessionId":"S","message":"{\"id\":1,\"method\":\"Page.navigate\",\"params\":{\"url\":\"\\u0063hrome-extension://lfbahamapdlbimlffmhiomfdemnjhjkc/worker.js\"}}"}}"#;
        assert!(denied(&f, parse(raw)));
        let nested = json!({"message": "{\"params\":{\"url\":\"\\u0063hrome-extension://x/\"}}"});
        assert!(f.forbidden_reference(&nested).is_some());
        // Escapes a script would decode are decoded too.
        assert!(denied(
            &f,
            json!({"id": 6, "method": "Runtime.evaluate",
                   "params": {"expression": "location = '\\u0063hrome://extensions'"}})
        ));
        assert!(denied(
            &f,
            json!({"id": 6, "method": "Runtime.evaluate",
                   "params": {"expression": "open('\\x63hrome-extension://lfbahamapdlbimlffmhiomfdemnjhjkc/')"}})
        ));
        // The JSON-escaped spelling of the raw request is decoded by the parser before the check.
        let escaped =
            r#"{"id":7,"method":"Page.navigate","params":{"url":"\u0063hrome://extensions"}}"#;
        assert!(denied(&f, parse(escaped)));
    }

    #[test]
    fn inbound_tunnel_messages_and_unparsable_messages_are_dropped() {
        let mut f = filter();
        let tunnelled = json!({"method": "Target.receivedMessageFromTarget",
            "params": {"sessionId": "N", "message": "{\"id\":1,\"result\":{}}"}});
        assert_eq!(f.inbound(&tunnelled.to_string()), Inbound::Drop);
        assert_eq!(f.inbound("not json"), Inbound::Drop);
        assert_eq!(f.inbound(r#"{"id":1,"result":"#), Inbound::Drop);
    }

    #[test]
    fn requests_naming_the_extension_or_internal_pages_are_denied_in_any_spelling() {
        let f = filter();
        for url in [
            WORKER_URL,
            "CHROME-EXTENSION://LFBAHAMAPDLBIMLFFMHIOMFDEMNJHJKC/worker.js",
            "chrome-extension://%6cfbahamapdlbimlffmhiomfdemnjhjkc/worker.js",
            "chrome-ext\tension://lfbahamapdlbimlffmhiomfdemnjhjkc/",
            "chrome-extension://someotherextensionidxxxxxxxxxxxx/",
            "chrome://extensions",
            "chrome:extensions",
            "Chrome://inspect/#service-workers",
            "chrome://serviceworker-internals",
            "devtools://devtools/bundled/inspector.html",
            "chrome-devtools://devtools/bundled/inspector.html",
            "view-source:chrome://extensions",
            // Review M-a.
            "about:inspect",
            "ABOUT:extensions",
            "about://inspect",
            "about:serviceworker-internals",
            "chrome-untrusted://print/",
            "chrome-search://local-ntp/",
        ] {
            assert!(
                denied(
                    &f,
                    json!({"id": 1, "method": "Page.navigate", "params": {"url": url}})
                ),
                "{url}"
            );
            assert!(
                denied(
                    &f,
                    json!({"id": 1, "method": "Target.createTarget", "params": {"url": url}})
                ),
                "{url}"
            );
        }
        for url in ["about:blank", "about:blank#top", "about:srcdoc"] {
            assert_eq!(
                f.check_request(
                    &json!({"id": 1, "method": "Target.createTarget", "params": {"url": url}})
                ),
                RequestVerdict::Forward,
                "{url}"
            );
        }
        // The ID anywhere in the parameters, even outside a URL, and in an object key.
        assert!(denied(
            &f,
            json!({"id": 1, "method": "Storage.getStorageKey", "params": {"origin": ID}})
        ));
        assert!(denied(
            &f,
            json!({"id": 1, "method": "Runtime.evaluate", "params": {"x": {(ID): 1}}})
        ));
    }

    #[test]
    fn sessions_are_checked_against_their_target() {
        let mut f = filter_with_page_session();
        // A session the filter never saw being created is refused.
        assert!(denied(
            &f,
            json!({"id": 1, "method": "Runtime.evaluate", "params": {"expression": "1"},
                   "sessionId": "FORGED"})
        ));
        // A session opened by a flat attach is mapped from the response.
        let attach = json!({"id": 2, "method": "Target.attachToTarget",
                            "params": {"targetId": "P2", "flatten": true}});
        f.note_forwarded(&attach);
        let response = json!({"id": 2, "result": {"sessionId": "S2"}}).to_string();
        assert_eq!(f.inbound(&response), Inbound::Deliver(response.clone()));
        assert_eq!(
            f.check_request(&json!({"id": 3, "method": "Page.reload", "sessionId": "S2"})),
            RequestVerdict::LookupTargets(vec!["P2".to_string()])
        );
        // A detached session is forgotten, so it is refused afterwards.
        let detached = json!({"method": "Target.detachedFromTarget",
                              "params": {"sessionId": "S2", "targetId": "P2"}})
        .to_string();
        assert_eq!(f.inbound(&detached), Inbound::Deliver(detached.clone()));
        assert!(denied(
            &f,
            json!({"id": 4, "method": "Page.reload", "sessionId": "S2"})
        ));
    }

    #[test]
    fn a_session_on_a_target_that_becomes_an_extension_target_is_refused_and_detached() {
        // Review H2: page `P` is attached as session `S`, then turns into an extension page.
        let mut f = filter_with_page_session();
        let changed = json!({"method": "Target.targetInfoChanged", "params": {"targetInfo": {
            "targetId": "P", "type": "page", "title": "", "url": WORKER_URL, "attached": true}}});
        assert_eq!(f.inbound(&changed.to_string()), Inbound::Drop);
        let commands: Vec<Value> = f.take_commands().iter().map(|c| parse(c)).collect();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0]["method"], "Target.detachFromTarget");
        assert_eq!(commands[0]["params"]["sessionId"], "S");
        assert!(denied(
            &f,
            json!({"id": 1, "method": "Runtime.evaluate", "params": {"expression": "1"},
                   "sessionId": "S"})
        ));
        let event = json!({"method": "Runtime.consoleAPICalled", "params": {}, "sessionId": "S"});
        assert_eq!(f.inbound(&event.to_string()), Inbound::Drop);

        // Without any event: the per-command lookup of the session's target finds it.
        let mut f = filter_with_page_session();
        let request = json!({"id": 2, "method": "Runtime.evaluate",
                             "params": {"expression": "1"}, "sessionId": "S"});
        let RequestVerdict::LookupTargets(targets) = f.check_request(&request) else {
            panic!("a session command is looked up");
        };
        assert_eq!(targets, vec!["P".to_string()]);
        let (id, _) = f.lookup_command("P");
        let mut became = page_info("P");
        became["url"] = Value::String(WORKER_URL.to_string());
        assert!(f.lookup_result("P", &json!({"id": id, "result": {"targetInfo": became}})));
        assert_eq!(f.take_commands().len(), 1, "the session is detached");
        assert!(denied(&f, request));
    }

    #[test]
    fn daemon_request_ids_are_reserved() {
        let f = filter();
        assert!(denied(
            &f,
            json!({"id": AGENT_ID_LIMIT, "method": "Page.reload"})
        ));
        assert!(denied(
            &f,
            json!({"id": 2_100_000_000u64, "method": "Page.reload"})
        ));
        assert_eq!(
            f.check_request(&json!({"id": AGENT_ID_LIMIT - 1, "method": "Page.reload"})),
            RequestVerdict::Forward
        );
    }

    #[test]
    fn an_auto_attach_to_the_worker_is_hidden_and_detached() {
        let mut f = filter();
        let event = json!({"method": "Target.attachedToTarget", "params": {
            "sessionId": "S", "targetInfo": worker_info("W"), "waitingForDebugger": true}});
        assert_eq!(f.inbound(&event.to_string()), Inbound::Drop);
        let commands: Vec<Value> = f.take_commands().iter().map(|c| parse(c)).collect();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0]["method"], "Runtime.runIfWaitingForDebugger");
        assert_eq!(commands[0]["sessionId"], "S");
        assert_eq!(commands[1]["method"], "Target.detachFromTarget");
        assert_eq!(commands[1]["params"]["sessionId"], "S");
        assert!(
            commands[1].get("sessionId").is_none(),
            "sent on the root session"
        );
        for command in &commands {
            assert!(ExtensionCdpFilter::is_internal_id(
                command["id"].as_u64().unwrap()
            ));
        }
        // The session and the target are now refused, and their traffic is hidden.
        assert!(denied(
            &f,
            json!({"id": 1, "method": "Runtime.evaluate", "params": {"expression": "1"},
                   "sessionId": "S"})
        ));
        assert!(denied(
            &f,
            json!({"id": 1, "method": "Target.detachFromTarget", "params": {"sessionId": "S"}})
        ));
        assert!(denied(
            &f,
            json!({"id": 1, "method": "Target.closeTarget", "params": {"targetId": "W"}})
        ));
        for hidden in [
            json!({"method": "Runtime.consoleAPICalled", "params": {}, "sessionId": "S"}),
            json!({"method": "Target.detachedFromTarget", "params": {"sessionId": "S"}}),
            json!({"method": "Target.targetDestroyed", "params": {"targetId": "W"}}),
            json!({"id": commands[1]["id"], "result": {}}),
        ] {
            assert_eq!(f.inbound(&hidden.to_string()), Inbound::Drop, "{hidden}");
        }
    }

    #[test]
    fn a_nested_auto_attach_is_detached_on_its_parent_session() {
        let mut f = filter();
        let event = json!({"method": "Target.attachedToTarget", "sessionId": "PARENT",
            "params": {"sessionId": "S", "targetInfo": worker_info("W"), "waitingForDebugger": false}});
        assert_eq!(f.inbound(&event.to_string()), Inbound::Drop);
        let commands = f.take_commands();
        assert_eq!(commands.len(), 1, "no resume when nothing waits");
        assert_eq!(parse(&commands[0])["sessionId"], "PARENT");
    }

    #[test]
    fn target_lists_and_events_hide_the_extension() {
        let mut f = filter();
        // Every response is rewritten, with no bookkeeping of the request that it answers
        // (review low: a bounded pending list could be outrun).
        let response =
            json!({"id": 7, "result": {"targetInfos": [page_info("P"), worker_info("W")]}});
        let Inbound::Deliver(delivered) = f.inbound(&response.to_string()) else {
            panic!("the response was dropped");
        };
        let delivered = parse(&delivered);
        let infos = delivered["result"]["targetInfos"].as_array().unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0]["targetId"], "P");
        // The hidden worker is known now.
        assert!(denied(
            &f,
            json!({"id": 8, "method": "Target.attachToTarget",
                   "params": {"targetId": "W", "flatten": true}})
        ));

        let info = json!({"id": 9, "result": {"targetInfo": worker_info("W")}});
        let Inbound::Deliver(delivered) = f.inbound(&info.to_string()) else {
            panic!("dropped");
        };
        let delivered = parse(&delivered);
        assert_eq!(delivered["id"], 9);
        assert!(delivered.get("result").is_none());
        assert!(delivered["error"].is_object());

        for event in [
            json!({"method": "Target.targetCreated", "params": {"targetInfo": worker_info("W2")}}),
            json!({"method": "Target.targetInfoChanged", "params": {"targetInfo": worker_info("W2")}}),
            json!({"method": "ServiceWorker.workerRegistrationUpdated", "params": {"registrations": [
                {"registrationId": "1", "scopeURL": "chrome-extension://lfbahamapdlbimlffmhiomfdemnjhjkc/",
                 "isDeleted": false}]}}),
        ] {
            assert_eq!(f.inbound(&event.to_string()), Inbound::Drop, "{event}");
        }
        // Ordinary events and responses pass untouched.
        let page_event =
            json!({"method": "Target.targetCreated", "params": {"targetInfo": page_info("P2")}})
                .to_string();
        assert_eq!(f.inbound(&page_event), Inbound::Deliver(page_event.clone()));
        let response = json!({"id": 10, "result": {"frameId": "F"}}).to_string();
        assert_eq!(f.inbound(&response), Inbound::Deliver(response.clone()));
    }

    #[test]
    fn internal_ids_stay_in_the_daemon_range_and_wrap() {
        let mut f = filter();
        f.next_internal = INTERNAL_ID_MAX;
        let (first, _) = f.lookup_command("A");
        let (second, _) = f.lookup_command("B");
        assert_eq!(first, INTERNAL_ID_MAX);
        assert_eq!(second, INTERNAL_ID_BASE);
        assert!(ExtensionCdpFilter::is_internal_id(second));
        assert!(!ExtensionCdpFilter::is_internal_id(AGENT_ID_LIMIT + 1));
    }

    #[test]
    fn tracking_is_bounded_and_fails_closed() {
        let mut f = filter();
        for i in 0..(MAX_TRACKED + 10) {
            f.denied_sessions.insert(&format!("S{i}"));
        }
        assert_eq!(f.denied_sessions.order.len(), MAX_TRACKED);
        for i in 0..(MAX_SESSIONS + 3) {
            f.track_session(&format!("L{i}"), "P", None);
        }
        assert_eq!(f.sessions.len(), MAX_SESSIONS);
        // An evicted session is unknown, so it is refused.
        assert!(denied(
            &f,
            json!({"id": 1, "method": "Page.reload", "sessionId": "L0"})
        ));
        // Attaches beyond the pending bound are refused, never left unmapped.
        for i in 0..MAX_PENDING_ATTACHES {
            f.note_forwarded(&json!({"id": i, "method": "Target.attachToTarget",
                                     "params": {"targetId": "P", "flatten": true}}));
        }
        assert!(denied(
            &f,
            json!({"id": 999, "method": "Target.attachToTarget",
                   "params": {"targetId": "P", "flatten": true}})
        ));
    }

    #[test]
    fn normalization_decodes_once_and_drops_url_whitespace() {
        assert_eq!(normalize("A%42c\td"), "abcd");
        assert_eq!(normalize("%2"), "%2");
        assert_eq!(normalize("%zz"), "%zz");
        assert_eq!(normalize("%2541"), "%41", "decoded once, like a URL parser");
        assert_eq!(normalize("\\u0063h\\x72ome"), "chrome");
        assert_eq!(normalize("\\u00zz\\x"), "\\u00zz\\x");
        assert!(names_scheme("chrome://x", "chrome:"));
        assert!(names_scheme("x chrome:extensions", "chrome:"));
        assert!(!names_scheme("chrome: 1", "chrome:"));
        assert!(!names_scheme("chrome:", "chrome:"));
        assert!(names_internal_about_page("about:inspect"));
        assert!(!names_internal_about_page("about:blank"));
        assert!(!names_internal_about_page("read about: this"));
    }
}
