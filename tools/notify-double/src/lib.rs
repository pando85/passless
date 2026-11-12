//! Scripted fake `org.freedesktop.Notifications` server for the E2E harness.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Map, Value as Json, json};
use thiserror::Error;
use zbus::Variant;

pub mod cli;
pub mod server;

pub const WELL_KNOWN_NAME: &str = "org.freedesktop.Notifications";
pub const OBJECT_PATH: &str = "/org/freedesktop/Notifications";

/// Reason 2: dismissed by the user.
pub const REASON_DISMISSED: u32 = 2;
/// Reason 3: closed by a call to `CloseNotification`.
pub const REASON_CLOSED_BY_CALL: u32 = 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScriptError {
    #[error("empty script step")]
    Empty,
    #[error("invalid delay '{0}' (expected milliseconds)")]
    InvalidDelay(String),
    #[error("empty action key in '{0}'")]
    EmptyAction(String),
    #[error("unknown script step '{0}'")]
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepAction {
    /// Emit nothing.
    Ignore,
    /// Emit `ActionInvoked` with this key, then `NotificationClosed` (dismissed).
    Invoke(String),
    /// Emit only `NotificationClosed` (dismissed).
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub action: StepAction,
    pub delay_ms: u64,
    text: String,
}

impl Step {
    /// The original spec text of this step.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

fn parse_delay(s: &str) -> Result<u64, ScriptError> {
    s.trim()
        .parse()
        .map_err(|_| ScriptError::InvalidDelay(s.to_string()))
}

/// The action key `approve` invokes: Passless's "Allow always" (ADR 0014 section 8.1).
pub const APPROVE_ACTION: &str = "allow_always";

/// Which notification server the double behaves like.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Emulation {
    /// A specification-conforming server: unique ids, `CloseNotification` closes.
    #[default]
    Spec,
    /// notify-osd 1.0 as observed on Ubuntu: `GetServerInformation` is [`NOTIFY_OSD_SERVER_INFORMATION`]
    /// (use [`NOTIFY_OSD_CAPABILITIES`], which lacks `actions`); a notification with actions is a
    /// fallback dialog whose `Notify` returns id 0, every time; a click emits
    /// `ActionInvoked(0, key)` then `NotificationClosed(0, 3)`; `CloseNotification` closes nothing.
    NotifyOsd,
}

/// notify-osd's `GetServerInformation` reply: name, vendor, version, spec version.
pub const NOTIFY_OSD_SERVER_INFORMATION: (&str, &str, &str, &str) =
    ("notify-osd", "Canonical Ltd", "1.0", "1.1");

/// notify-osd's `GetCapabilities` reply (no `actions`).
pub const NOTIFY_OSD_CAPABILITIES: &[&str] = &[
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
];

/// The key a scripted `Invoke(key)` emits for a notification with `actions` (a flat
/// `[key, label, ...]` list): the notification's own action key that equals `key` or extends it as
/// `<key>:<suffix>` (clients may make their keys unique per notification), otherwise `key`.
pub fn resolve_action_key(key: &str, actions: &[String]) -> String {
    let keys = || actions.iter().step_by(2);
    if let Some(exact) = keys().find(|k| *k == key) {
        return exact.clone();
    }
    keys()
        .find(|k| {
            k.strip_prefix(key)
                .is_some_and(|rest| rest.starts_with(':'))
        })
        .cloned()
        .unwrap_or_else(|| key.to_string())
}

/// Parse a single script step.
///
/// Grammar: `approve[:ms]` (invokes [`APPROVE_ACTION`]), `deny[:ms]`, `ignore`, `close[:ms]`,
/// `invoke=<key>[:ms]`.
pub fn parse_step(spec: &str) -> Result<Step, ScriptError> {
    let text = spec.trim();
    if text.is_empty() {
        return Err(ScriptError::Empty);
    }
    let (head, delay) = match text.split_once(':') {
        Some((head, delay)) => (head, Some(delay)),
        None => (text, None),
    };
    let delay_ms = delay.map(parse_delay).transpose()?.unwrap_or(0);
    let action = if let Some(key) = head.strip_prefix("invoke=") {
        if key.is_empty() {
            return Err(ScriptError::EmptyAction(text.to_string()));
        }
        StepAction::Invoke(key.to_string())
    } else {
        match head {
            "approve" => StepAction::Invoke(APPROVE_ACTION.to_string()),
            "deny" => StepAction::Invoke("deny".to_string()),
            "close" => StepAction::Close,
            "ignore" if delay.is_none() => StepAction::Ignore,
            _ => return Err(ScriptError::Unknown(text.to_string())),
        }
    };
    Ok(Step {
        action,
        delay_ms,
        text: text.to_string(),
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Script {
    steps: Vec<Step>,
}

impl Script {
    pub fn new(steps: Vec<Step>) -> Self {
        Self { steps }
    }

    pub fn parse_specs<I, S>(specs: I) -> Result<Self, ScriptError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let steps = specs
            .into_iter()
            .map(|s| parse_step(s.as_ref()))
            .collect::<Result<_, _>>()?;
        Ok(Self { steps })
    }

    /// Parse a comma-separated list of steps.
    pub fn parse_list(list: &str) -> Result<Self, ScriptError> {
        Self::parse_specs(list.split(',').filter(|s| !s.trim().is_empty()))
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Step for the `n`th (zero-based) new notification; the last step repeats.
    /// `None` when the script is empty (meaning `ignore`).
    pub fn step_for(&self, n: usize) -> Option<&Step> {
        self.steps.get(n).or_else(|| self.steps.last())
    }
}

/// Convert a D-Bus value to JSON on a best-effort basis.
pub fn value_to_json(value: &Variant<'_>) -> Json {
    match value {
        Variant::U8(v) => json!(v),
        Variant::Bool(v) => json!(v),
        Variant::I16(v) => json!(v),
        Variant::U16(v) => json!(v),
        Variant::I32(v) => json!(v),
        Variant::U32(v) => json!(v),
        Variant::I64(v) => json!(v),
        Variant::U64(v) => json!(v),
        Variant::F64(v) => json!(v),
        Variant::Str(v) => json!(v.as_str()),
        Variant::Signature(v) => json!(v.to_string()),
        Variant::ObjectPath(v) => json!(v.as_str()),
        Variant::Variant(v) => value_to_json(v),
        Variant::Array(a) => Json::Array(a.inner().iter().map(value_to_json).collect()),
        Variant::Structure(s) => Json::Array(s.fields().iter().map(value_to_json).collect()),
        Variant::Dict(d) => {
            let mut map = Map::new();
            for (k, v) in d.iter() {
                let key = match k {
                    Variant::Str(s) => s.as_str().to_string(),
                    other => format!("{other:?}"),
                };
                map.insert(key, value_to_json(v));
            }
            Json::Object(map)
        }
        other => json!(format!("{other:?}")),
    }
}

/// One log event. Serialized with an `event` tag.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event")]
pub enum Event {
    Notify {
        sender: Option<String>,
        app_name: String,
        replaces_id: u32,
        app_icon: String,
        summary: String,
        body: String,
        actions: Vec<String>,
        hints: Json,
        expire_timeout: i32,
        id: u32,
        step: String,
    },
    CloseNotification {
        sender: Option<String>,
        id: u32,
    },
    GetCapabilities {
        sender: Option<String>,
    },
    GetServerInformation {
        sender: Option<String>,
    },
    ActionInvoked {
        id: u32,
        action: String,
        delay_ms: u64,
    },
    NotificationClosed {
        id: u32,
        reason: u32,
        origin: &'static str,
    },
    Cancelled {
        id: u32,
        reason: &'static str,
    },
}

#[derive(Serialize)]
struct Record<'a> {
    ts_ms: u128,
    seq: u64,
    #[serde(flatten)]
    event: &'a Event,
}

struct LogInner {
    file: File,
    seq: u64,
}

/// Append-only JSON-lines log, flushed after every event.
pub struct LogWriter {
    inner: Mutex<LogInner>,
}

impl LogWriter {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            inner: Mutex::new(LogInner { file, seq: 0 }),
        })
    }

    pub fn write(&self, event: &Event) -> std::io::Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.seq += 1;
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let record = Record {
            ts_ms,
            seq: inner.seq,
            event,
        };
        let mut line = serde_json::to_vec(&record).map_err(std::io::Error::other)?;
        line.push(b'\n');
        inner.file.write_all(&line)?;
        inner.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_steps() {
        let s = parse_step("approve").unwrap();
        assert_eq!(s.action, StepAction::Invoke("allow_always".into()));
        assert_eq!(s.delay_ms, 0);
        let s = parse_step("deny:250").unwrap();
        assert_eq!(s.action, StepAction::Invoke("deny".into()));
        assert_eq!(s.delay_ms, 250);
        assert_eq!(parse_step("ignore").unwrap().action, StepAction::Ignore);
        let s = parse_step("close:10").unwrap();
        assert_eq!(s.action, StepAction::Close);
        assert_eq!(s.delay_ms, 10);
        assert_eq!(s.text(), "close:10");
    }

    #[test]
    fn parses_invoke() {
        let s = parse_step("invoke=default").unwrap();
        assert_eq!(s.action, StepAction::Invoke("default".into()));
        let s = parse_step("invoke=weird key:5").unwrap();
        assert_eq!(s.action, StepAction::Invoke("weird key".into()));
        assert_eq!(s.delay_ms, 5);
    }

    #[test]
    fn invoked_keys_resolve_to_the_notifications_own_keys() {
        let actions: Vec<String> = ["allow_always:ab12", "Allow always", "deny:ab12", "Deny"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            resolve_action_key("allow_always", &actions),
            "allow_always:ab12"
        );
        assert_eq!(resolve_action_key("deny", &actions), "deny:ab12");
        // A label is never a key, and an unrelated key stays as it is.
        assert_eq!(resolve_action_key("Deny", &actions), "Deny");
        assert_eq!(resolve_action_key("default", &actions), "default");
        let plain: Vec<String> = ["deny", "Deny", "deny_all", "x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(resolve_action_key("deny", &plain), "deny");
        assert_eq!(resolve_action_key("allow_always", &plain), "allow_always");
    }

    #[test]
    fn rejects_bad_steps() {
        assert_eq!(parse_step(""), Err(ScriptError::Empty));
        assert!(matches!(
            parse_step("approve:x"),
            Err(ScriptError::InvalidDelay(_))
        ));
        assert!(matches!(
            parse_step("invoke="),
            Err(ScriptError::EmptyAction(_))
        ));
        assert!(matches!(
            parse_step("ignore:5"),
            Err(ScriptError::Unknown(_))
        ));
        assert!(matches!(parse_step("nope"), Err(ScriptError::Unknown(_))));
    }

    #[test]
    fn step_selection_repeats_last() {
        let script = Script::parse_list("approve, deny:5,ignore").unwrap();
        assert_eq!(script.len(), 3);
        assert_eq!(script.step_for(0).unwrap().text(), "approve");
        assert_eq!(script.step_for(1).unwrap().text(), "deny:5");
        assert_eq!(script.step_for(2).unwrap().text(), "ignore");
        assert_eq!(script.step_for(3).unwrap().text(), "ignore");
        assert_eq!(script.step_for(100).unwrap().text(), "ignore");
    }

    #[test]
    fn empty_script_has_no_steps() {
        let script = Script::parse_list("").unwrap();
        assert!(script.is_empty());
        assert!(script.step_for(0).is_none());
    }

    #[test]
    fn hints_convert_to_json() {
        assert_eq!(value_to_json(&Variant::from(true)), json!(true));
        assert_eq!(value_to_json(&Variant::from("x")), json!("x"));
        assert_eq!(value_to_json(&Variant::from(7u8)), json!(7));
        assert_eq!(
            value_to_json(&Variant::from(vec![1u8, 2, 3])),
            json!([1, 2, 3])
        );
    }

    #[test]
    fn log_lines_have_ts_seq_and_event() {
        let dir = std::env::temp_dir().join(format!("notify-double-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.jsonl");
        let _ = std::fs::remove_file(&path);
        let log = LogWriter::open(&path).unwrap();
        log.write(&Event::Cancelled {
            id: 1,
            reason: "CloseNotification",
        })
        .unwrap();
        log.write(&Event::GetCapabilities { sender: None }).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<Json> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[0]["event"], "Cancelled");
        assert_eq!(lines[0]["seq"], 1);
        assert_eq!(lines[1]["seq"], 2);
        assert!(lines[0]["ts_ms"].is_number());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
