//! The extension filter of pipe-mode `browser-control` (ADR 0014 sections 4.3 and 11, review M3).
//!
//! In pipe mode every CDP command of the agent goes through the daemon, so the daemon keeps the
//! agent away from the Passless extension: the extension's service worker holds the daemon bearer
//! and reports request origins, and a CDP session on it could read the bearer, forge request
//! details or detach the WebAuthn proxy. The filter
//!
//! - denies the `Extensions` domain, `Target.exposeDevToolsProtocol` (it would hand page script an
//!   unfiltered CDP channel to the browser) and the `ServiceWorker` commands that inspect or stop
//!   workers by version (`inspectWorker`, `stopWorker`, `stopAllWorkers`), which cannot be
//!   attributed to a worker without tracking every registration;
//! - denies a command whose `targetId` names an extension target (looked up with a daemon-issued
//!   `Target.getTargetInfo` when the filter does not know the target yet), whose `sessionId`
//!   (top-level or in `params`) is a session on an extension target, or whose parameters name the
//!   extension or a browser-internal page (`chrome-extension:`, the extension ID, `chrome:`,
//!   `devtools:`), after the normalization a URL parser applies (tabs and newlines dropped,
//!   percent escapes decoded once, lowercase);
//! - hides extension targets from the agent: `Target.getTargets` results lose them, and target
//!   events about them are dropped. An auto-attach (`Target.setAutoAttach`) that reaches the
//!   extension worker is dropped too, and the daemon detaches that session at once (resuming the
//!   worker first if it waits for a debugger).
//!
//! The filter never forwards an agent command with an ID in the daemon's range (from
//! [`AGENT_ID_LIMIT`]); the responses to the filter's own commands are swallowed.
//!
//! Port mode exposes Chromium's DevTools listener directly and is not filtered (ADR 0014
//! section 15).

use std::collections::{HashSet, VecDeque};

use serde_json::{Value, json};

/// Agent request IDs must stay below this. The daemon's own CDP commands use IDs from here up
/// (`START_URL_CDP_ID` and the filter's lookups).
pub const AGENT_ID_LIMIT: u64 = 2_000_000_000;
/// The filter's own commands (target lookups, detaches) use IDs in this range. CDP IDs are 32-bit
/// signed integers in Chromium.
const INTERNAL_ID_BASE: u64 = 2_100_000_000;
const INTERNAL_ID_MAX: u64 = i32::MAX as u64;
/// How many extension targets and sessions the filter remembers. A session that was detached is
/// dead in the browser, so forgetting the oldest one does not reopen it.
const MAX_TRACKED: usize = 256;
/// How many forwarded requests whose responses may need rewriting are remembered.
const MAX_PENDING: usize = 64;

const DENIED_METHODS: &[&str] = &[
    "Target.exposeDevToolsProtocol",
    "ServiceWorker.inspectWorker",
    "ServiceWorker.stopWorker",
    "ServiceWorker.stopAllWorkers",
];

/// What to do with an agent's CDP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestVerdict {
    Forward,
    /// The request names a target the filter does not know: look it up first
    /// ([`ExtensionCdpFilter::lookup_command`], [`ExtensionCdpFilter::lookup_result`]).
    LookupTarget(String),
    Deny(String),
}

/// What to do with a message from the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Deliver(String),
    /// Hide the message from the agent and send `commands` (daemon-issued) to the browser.
    Drop {
        commands: Vec<String>,
    },
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

/// Per-lease state of the filter (see the module documentation).
#[derive(Debug)]
pub struct ExtensionCdpFilter {
    /// The extension ID, lowercase.
    extension_id: String,
    targets: BoundedSet,
    sessions: BoundedSet,
    /// Forwarded agent requests whose responses are rewritten: (id, method).
    pending: VecDeque<(u64, String)>,
    next_internal: u64,
}

impl ExtensionCdpFilter {
    pub fn new(extension_id: &str) -> Self {
        Self {
            extension_id: extension_id.to_ascii_lowercase(),
            targets: BoundedSet::default(),
            sessions: BoundedSet::default(),
            pending: VecDeque::new(),
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
        if object
            .get("sessionId")
            .and_then(Value::as_str)
            .is_some_and(|session| self.sessions.contains(session))
        {
            return deny("the session belongs to the Passless extension");
        }
        let Some(params) = object.get("params") else {
            return RequestVerdict::Forward;
        };
        if params
            .get("sessionId")
            .and_then(Value::as_str)
            .is_some_and(|session| self.sessions.contains(session))
        {
            return deny("the session belongs to the Passless extension");
        }
        if let Some(reason) = self.forbidden_reference(params) {
            return deny(reason);
        }
        match params.get("targetId").and_then(Value::as_str) {
            Some(target) if self.targets.contains(target) => {
                deny("the target is the Passless extension")
            }
            Some(target) => RequestVerdict::LookupTarget(target.to_string()),
            None => RequestVerdict::Forward,
        }
    }

    /// Remember a forwarded agent request whose response may need rewriting.
    pub fn note_forwarded(&mut self, request: &Value) {
        let method = request.get("method").and_then(Value::as_str);
        let id = request.get("id").and_then(Value::as_u64);
        if let (Some(method @ ("Target.getTargets" | "Target.getTargetInfo")), Some(id)) =
            (method, id)
        {
            if self.pending.len() >= MAX_PENDING {
                self.pending.pop_front();
            }
            self.pending.push_back((id, method.to_string()));
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

    /// Record the lookup's response. True when `target_id` is an extension target.
    pub fn lookup_result(&mut self, target_id: &str, response: &Value) -> bool {
        let extension = response
            .pointer("/result/targetInfo")
            .is_some_and(|info| self.is_extension_target(info));
        if extension {
            self.remember_extension_target(target_id);
        }
        extension
    }

    /// The ID of a response to one of the filter's own commands.
    pub fn is_internal_id(id: u64) -> bool {
        id >= INTERNAL_ID_BASE
    }

    /// Filter a message from the browser before the agent sees it.
    pub fn inbound(&mut self, raw: &str) -> Inbound {
        let Ok(mut message) = serde_json::from_str::<Value>(raw) else {
            return Inbound::Deliver(raw.to_string());
        };
        if let Some(id) = message.get("id").and_then(Value::as_u64) {
            if Self::is_internal_id(id) {
                return Inbound::Drop {
                    commands: Vec::new(),
                };
            }
            return match self.take_pending(id) {
                Some(method) if self.rewrite_response(&method, &mut message) => {
                    Inbound::Deliver(message.to_string())
                }
                _ => Inbound::Deliver(raw.to_string()),
            };
        }
        let hidden = || Inbound::Drop {
            commands: Vec::new(),
        };
        if message
            .get("sessionId")
            .and_then(Value::as_str)
            .is_some_and(|session| self.sessions.contains(session))
        {
            return hidden();
        }
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let target_info = params.get("targetInfo");
        match method {
            "Target.attachedToTarget" => {
                if target_info.is_some_and(|info| self.is_extension_target(info)) {
                    return self.detach_extension_session(&message, &params);
                }
            }
            "Target.targetCreated" | "Target.targetInfoChanged" => {
                if let Some(info) = target_info
                    && self.is_extension_target(info)
                {
                    if let Some(target) = info.get("targetId").and_then(Value::as_str) {
                        self.remember_extension_target(target);
                    }
                    return hidden();
                }
            }
            "Target.targetDestroyed"
            | "Target.targetCrashed"
            | "Target.detachedFromTarget"
            | "Target.receivedMessageFromTarget" => {
                let target = params.get("targetId").and_then(Value::as_str);
                let session = params.get("sessionId").and_then(Value::as_str);
                if target.is_some_and(|t| self.targets.contains(t))
                    || session.is_some_and(|s| self.sessions.contains(s))
                {
                    return hidden();
                }
            }
            _ => {}
        }
        // Any other event that names the extension (service worker registrations, for example).
        if mentions(&params, &self.extension_id) {
            return hidden();
        }
        Inbound::Deliver(raw.to_string())
    }

    /// An auto-attach reached an extension target: remember the session, hide the event, and
    /// detach the session (resuming the target first if it waits for a debugger).
    fn detach_extension_session(&mut self, message: &Value, params: &Value) -> Inbound {
        if let Some(target) = params
            .pointer("/targetInfo/targetId")
            .and_then(Value::as_str)
        {
            self.remember_extension_target(target);
        }
        let Some(session) = params.get("sessionId").and_then(Value::as_str) else {
            return Inbound::Drop {
                commands: Vec::new(),
            };
        };
        self.sessions.insert(session);
        let parent = message.get("sessionId").and_then(Value::as_str);
        let mut commands = Vec::new();
        if params.get("waitingForDebugger") == Some(&Value::Bool(true)) {
            commands.push(
                self.internal_command("Runtime.runIfWaitingForDebugger", json!({}), Some(session))
                    .1,
            );
        }
        commands.push(
            self.internal_command(
                "Target.detachFromTarget",
                json!({ "sessionId": session }),
                parent,
            )
            .1,
        );
        Inbound::Drop { commands }
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

    fn take_pending(&mut self, id: u64) -> Option<String> {
        let index = self
            .pending
            .iter()
            .position(|(pending, _)| *pending == id)?;
        self.pending.remove(index).map(|(_, method)| method)
    }

    /// Rewrite the response to a forwarded `Target.getTargets` or `Target.getTargetInfo`. True
    /// when the message changed.
    fn rewrite_response(&mut self, method: &str, message: &mut Value) -> bool {
        match method {
            "Target.getTargets" => {
                let Some(infos) = message
                    .pointer_mut("/result/targetInfos")
                    .and_then(Value::as_array_mut)
                else {
                    return false;
                };
                let mut hidden = Vec::new();
                infos.retain(|info| {
                    let extension = info
                        .get("url")
                        .and_then(Value::as_str)
                        .is_some_and(|url| normalize(url).contains(&self.extension_id));
                    if extension && let Some(target) = info.get("targetId").and_then(Value::as_str)
                    {
                        hidden.push(target.to_string());
                    }
                    !extension
                });
                for target in &hidden {
                    self.remember_extension_target(target);
                }
                !hidden.is_empty()
            }
            "Target.getTargetInfo" => {
                let extension = message
                    .pointer("/result/targetInfo")
                    .is_some_and(|info| self.is_extension_target(info));
                if !extension {
                    return false;
                }
                if let Some(target) = message
                    .pointer("/result/targetInfo/targetId")
                    .and_then(Value::as_str)
                {
                    self.remember_extension_target(target);
                }
                let id = message.get("id").cloned().unwrap_or(Value::Null);
                *message = json!({
                    "id": id,
                    "error": {"code": -32000, "message": "No target with given id found"},
                });
                true
            }
            _ => false,
        }
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
        info.get("url")
            .and_then(Value::as_str)
            .is_some_and(|url| normalize(url).contains(&self.extension_id))
    }

    /// Why `params` may not be forwarded, if a string in it names the extension or a
    /// browser-internal page.
    fn forbidden_reference(&self, params: &Value) -> Option<&'static str> {
        let mut found = None;
        visit_strings(params, &mut |text| {
            if found.is_some() {
                return;
            }
            let text = normalize(text);
            if text.contains(&self.extension_id) || text.contains("chrome-extension:") {
                found = Some("the request names an extension");
            } else if names_scheme(&text, "chrome:") || names_scheme(&text, "devtools:") {
                found = Some("the request names a browser-internal page");
            }
        });
        found
    }
}

/// Every string in `value`, object keys included.
fn visit_strings(value: &Value, visit: &mut dyn FnMut(&str)) {
    match value {
        Value::String(text) => visit(text),
        Value::Array(items) => items.iter().for_each(|item| visit_strings(item, visit)),
        Value::Object(map) => {
            for (key, item) in map {
                visit(key);
                visit_strings(item, visit);
            }
        }
        _ => {}
    }
}

fn mentions(value: &Value, needle: &str) -> bool {
    let mut found = false;
    visit_strings(value, &mut |text| {
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

/// What a URL parser does before it compares a scheme or a host: ASCII tabs and newlines are
/// dropped, percent escapes decoded once, and the result lowercased.
fn normalize(text: &str) -> String {
    let bytes: Vec<u8> = text
        .bytes()
        .filter(|byte| !matches!(byte, b'\t' | b'\n' | b'\r'))
        .collect();
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

    #[test]
    fn ordinary_automation_is_forwarded() {
        let f = filter();
        for request in [
            json!({"id": 1, "method": "Page.navigate", "params": {"url": "https://rp.test/"}}),
            json!({"id": 2, "method": "Runtime.evaluate", "params": {"expression": "1 + 1"},
                   "sessionId": "page-session"}),
            json!({"id": 3, "method": "Target.setAutoAttach",
                   "params": {"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}}),
            json!({"id": 4, "method": "Target.setDiscoverTargets", "params": {"discover": true}}),
            json!({"id": 5, "method": "Target.getTargets"}),
            json!({"id": 6, "method": "Target.createTarget", "params": {"url": "about:blank"}}),
            json!({"id": 7, "method": "Runtime.evaluate",
                   "params": {"expression": "navigator.userAgent.includes('Chrome')"}}),
        ] {
            assert_eq!(
                f.check_request(&request),
                RequestVerdict::Forward,
                "{request}"
            );
        }
    }

    #[test]
    fn a_target_command_is_looked_up_unless_the_target_is_known() {
        let mut f = filter();
        let attach = json!({"id": 1, "method": "Target.attachToTarget",
                            "params": {"targetId": "W", "flatten": true}});
        assert_eq!(
            f.check_request(&attach),
            RequestVerdict::LookupTarget("W".to_string())
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
            "Target.sendMessageToTarget",
            "Target.autoAttachRelated",
            "Target.openDevTools",
            "Target.getTargetInfo",
        ] {
            assert!(
                denied(
                    &f,
                    json!({"id": 2, "method": method, "params": {"targetId": "W"}})
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
    fn extension_domains_and_worker_controls_are_denied() {
        let f = filter();
        for method in [
            "Extensions.loadUnpacked",
            "Extensions.getStorageItems",
            "Extensions.uninstall",
            "Target.exposeDevToolsProtocol",
            "ServiceWorker.inspectWorker",
            "ServiceWorker.stopWorker",
            "ServiceWorker.stopAllWorkers",
        ] {
            assert!(denied(&f, json!({"id": 1, "method": method})), "{method}");
        }
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
            "view-source:chrome://extensions",
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
        let Inbound::Drop { commands } = f.inbound(&event.to_string()) else {
            panic!("the attach event reached the agent");
        };
        let commands: Vec<Value> = commands.iter().map(|c| parse(c)).collect();
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
            json!({"id": 1, "method": "Target.sendMessageToTarget",
                   "params": {"sessionId": "S", "message": "{}"}})
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
            assert!(
                matches!(f.inbound(&hidden.to_string()), Inbound::Drop { .. }),
                "{hidden}"
            );
        }
    }

    #[test]
    fn a_nested_auto_attach_is_detached_on_its_parent_session() {
        let mut f = filter();
        let event = json!({"method": "Target.attachedToTarget", "sessionId": "PARENT",
            "params": {"sessionId": "S", "targetInfo": worker_info("W"), "waitingForDebugger": false}});
        let Inbound::Drop { commands } = f.inbound(&event.to_string()) else {
            panic!("delivered");
        };
        assert_eq!(commands.len(), 1, "no resume when nothing waits");
        assert_eq!(parse(&commands[0])["sessionId"], "PARENT");
    }

    #[test]
    fn target_lists_and_events_hide_the_extension() {
        let mut f = filter();
        f.note_forwarded(&json!({"id": 7, "method": "Target.getTargets"}));
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
            json!({"id": 8, "method": "Target.attachToTarget", "params": {"targetId": "W"}})
        ));

        f.note_forwarded(&json!({"id": 9, "method": "Target.getTargetInfo"}));
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
            assert!(
                matches!(f.inbound(&event.to_string()), Inbound::Drop { .. }),
                "{event}"
            );
        }
        // Ordinary events and responses pass untouched.
        let page_event =
            json!({"method": "Target.targetCreated", "params": {"targetInfo": page_info("P2")}})
                .to_string();
        assert_eq!(f.inbound(&page_event), Inbound::Deliver(page_event.clone()));
        let response = json!({"id": 10, "result": {"frameId": "F"}}).to_string();
        assert_eq!(f.inbound(&response), Inbound::Deliver(response.clone()));
        assert_eq!(
            f.inbound("not json"),
            Inbound::Deliver("not json".to_string())
        );
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
    fn tracking_is_bounded() {
        let mut f = filter();
        for i in 0..(MAX_TRACKED + 10) {
            f.sessions.insert(&format!("S{i}"));
        }
        assert_eq!(f.sessions.order.len(), MAX_TRACKED);
        assert!(!f.sessions.contains("S0"));
        assert!(f.sessions.contains(&format!("S{}", MAX_TRACKED + 9)));
        for i in 0..(MAX_PENDING + 5) {
            f.note_forwarded(&json!({"id": i, "method": "Target.getTargets"}));
        }
        assert_eq!(f.pending.len(), MAX_PENDING);
    }

    #[test]
    fn normalization_decodes_once_and_drops_url_whitespace() {
        assert_eq!(normalize("A%42c\td"), "abcd");
        assert_eq!(normalize("%2"), "%2");
        assert_eq!(normalize("%zz"), "%zz");
        assert_eq!(normalize("%2541"), "%41", "decoded once, like a URL parser");
        assert!(names_scheme("chrome://x", "chrome:"));
        assert!(names_scheme("x chrome:extensions", "chrome:"));
        assert!(!names_scheme("chrome: 1", "chrome:"));
        assert!(!names_scheme("chrome:", "chrome:"));
    }
}
