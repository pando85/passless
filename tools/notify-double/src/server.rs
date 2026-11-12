//! The `org.freedesktop.Notifications` interface implementation.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::time::sleep;
use zbus::message::Header;
use zbus::{Connection, Variant, interface};

use crate::{
    Emulation, Event, LogWriter, NOTIFY_OSD_SERVER_INFORMATION, OBJECT_PATH, REASON_CLOSED_BY_CALL,
    REASON_DISMISSED, Script, StepAction, WELL_KNOWN_NAME, resolve_action_key, value_to_json,
};

/// Delayed steps wait at least this long so signals follow the `Notify` reply.
const MIN_SIGNAL_DELAY_MS: u64 = 5;

pub struct Config {
    pub script: Script,
    pub capabilities: Vec<String>,
    pub server_name: String,
    pub emulation: Emulation,
}

#[derive(Default)]
struct State {
    next_id: u32,
    known: HashSet<u32>,
    new_count: usize,
    /// Scripted steps not yet run, by notification serial (ids are not unique under
    /// [`Emulation::NotifyOsd`]), with the id each was shown under.
    pending: HashMap<u64, u32>,
    next_serial: u64,
}

struct Shared {
    config: Config,
    log: Arc<LogWriter>,
    state: Mutex<State>,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn log(&self, event: &Event) {
        if let Err(e) = self.log.write(event) {
            eprintln!("notify-double: failed to write log: {e}");
        }
    }
}

pub struct NotificationDouble {
    shared: Arc<Shared>,
}

impl NotificationDouble {
    pub fn new(config: Config, log: Arc<LogWriter>) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                log,
                state: Mutex::new(State {
                    next_id: 1,
                    ..State::default()
                }),
            }),
        }
    }
}

fn sender_of(header: &Header<'_>) -> Option<String> {
    header.sender().map(|s| s.to_string())
}

async fn emit(
    conn: &Connection,
    member: &str,
    body: &(impl serde::Serialize + zbus::zvariant::DynamicType),
) -> zbus::Result<()> {
    conn.emit_signal(
        None::<zbus::names::BusName<'_>>,
        OBJECT_PATH,
        WELL_KNOWN_NAME,
        member,
        body,
    )
    .await
}

async fn emit_closed(
    shared: &Shared,
    conn: &Connection,
    id: u32,
    reason: u32,
    origin: &'static str,
) {
    match emit(conn, "NotificationClosed", &(id, reason)).await {
        Ok(()) => shared.log(&Event::NotificationClosed { id, reason, origin }),
        Err(e) => eprintln!("notify-double: emit NotificationClosed failed: {e}"),
    }
}

async fn run_step(
    shared: Arc<Shared>,
    conn: Connection,
    serial: u64,
    id: u32,
    action: StepAction,
    delay_ms: u64,
) {
    sleep(Duration::from_millis(delay_ms.max(MIN_SIGNAL_DELAY_MS))).await;
    // Claim the step; CloseNotification removes it first when it wins the race.
    if shared.state().pending.remove(&serial).is_none() {
        return;
    }
    // notify-osd's fallback dialog reports its close with reason 3 (observed: `ActionInvoked(0,
    // key)` then `NotificationClosed(0, 3)`).
    let close_reason = match shared.config.emulation {
        Emulation::Spec => REASON_DISMISSED,
        Emulation::NotifyOsd => REASON_CLOSED_BY_CALL,
    };
    match action {
        StepAction::Ignore => {}
        StepAction::Invoke(key) => {
            match emit(&conn, "ActionInvoked", &(id, key.as_str())).await {
                Ok(()) => shared.log(&Event::ActionInvoked {
                    id,
                    action: key,
                    delay_ms,
                }),
                Err(e) => {
                    eprintln!("notify-double: emit ActionInvoked failed: {e}");
                    return;
                }
            }
            emit_closed(&shared, &conn, id, close_reason, "script").await;
        }
        StepAction::Close => {
            emit_closed(&shared, &conn, id, close_reason, "script").await;
        }
    }
}

#[interface(name = "org.freedesktop.Notifications")]
impl NotificationDouble {
    async fn get_capabilities(&self, #[zbus(header)] header: Header<'_>) -> Vec<String> {
        self.shared.log(&Event::GetCapabilities {
            sender: sender_of(&header),
        });
        self.shared.config.capabilities.clone()
    }

    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: Vec<String>,
        hints: HashMap<String, Variant<'_>>,
        expire_timeout: i32,
    ) -> zbus::fdo::Result<u32> {
        let shared = &self.shared;
        // notify-osd shows a notification with actions as a fallback dialog and returns id 0 for
        // every one of them.
        let dialog = shared.config.emulation == Emulation::NotifyOsd && !actions.is_empty();
        let (serial, id, step) = {
            let mut st = shared.state();
            let serial = st.next_serial;
            st.next_serial += 1;
            let is_new = dialog || replaces_id == 0 || !st.known.contains(&replaces_id);
            let id = if dialog {
                0
            } else if replaces_id == 0 {
                let id = st.next_id;
                st.next_id += 1;
                id
            } else {
                st.next_id = st.next_id.max(replaces_id.saturating_add(1));
                replaces_id
            };
            st.known.insert(id);
            let step = if is_new {
                let n = st.new_count;
                st.new_count += 1;
                shared.config.script.step_for(n).cloned()
            } else {
                None
            };
            if step
                .as_ref()
                .is_some_and(|s| s.action != StepAction::Ignore)
            {
                st.pending.insert(serial, id);
            }
            (serial, id, step)
        };

        let hints_json = hints
            .iter()
            .map(|(k, v)| (k.clone(), value_to_json(v)))
            .collect();
        shared.log(&Event::Notify {
            sender: sender_of(&header),
            app_name: app_name.to_string(),
            replaces_id,
            app_icon: app_icon.to_string(),
            summary: summary.to_string(),
            body: body.to_string(),
            actions: actions.clone(),
            hints: serde_json::Value::Object(hints_json),
            expire_timeout,
            id,
            step: step
                .as_ref()
                .map_or_else(|| "none".to_string(), |s| s.text().to_string()),
        });

        if let Some(step) = step
            && step.action != StepAction::Ignore
        {
            let action = match step.action {
                StepAction::Invoke(key) => StepAction::Invoke(resolve_action_key(&key, &actions)),
                other => other,
            };
            tokio::spawn(run_step(
                Arc::clone(shared),
                conn.clone(),
                serial,
                id,
                action,
                step.delay_ms,
            ));
        }
        Ok(id)
    }

    async fn close_notification(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        id: u32,
    ) -> zbus::fdo::Result<()> {
        let shared = &self.shared;
        shared.log(&Event::CloseNotification {
            sender: sender_of(&header),
            id,
        });
        // notify-osd cannot close its fallback dialogs: the dialog stays, and a later click still
        // emits its action (the worst case a client must tolerate).
        if shared.config.emulation == Emulation::NotifyOsd {
            return Ok(());
        }
        let cancelled = {
            let mut st = shared.state();
            let before = st.pending.len();
            st.pending.retain(|_, pending_id| *pending_id != id);
            st.pending.len() != before
        };
        if cancelled {
            shared.log(&Event::Cancelled {
                id,
                reason: "CloseNotification",
            });
        }
        emit_closed(shared, conn, id, REASON_CLOSED_BY_CALL, "CloseNotification").await;
        Ok(())
    }

    async fn get_server_information(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> (String, String, String, String) {
        self.shared.log(&Event::GetServerInformation {
            sender: sender_of(&header),
        });
        match self.shared.config.emulation {
            Emulation::Spec => (
                self.shared.config.server_name.clone(),
                "passless".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
                "1.2".to_string(),
            ),
            Emulation::NotifyOsd => {
                let (name, vendor, version, spec) = NOTIFY_OSD_SERVER_INFORMATION;
                (
                    name.to_string(),
                    vendor.to_string(),
                    version.to_string(),
                    spec.to_string(),
                )
            }
        }
    }
}
