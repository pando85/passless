//! The `org.freedesktop.Notifications` interface implementation.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::time::sleep;
use zbus::message::Header;
use zbus::{Connection, Variant, interface};

use crate::{
    Event, LogWriter, OBJECT_PATH, REASON_CLOSED_BY_CALL, REASON_DISMISSED, Script, StepAction,
    WELL_KNOWN_NAME, value_to_json,
};

/// Delayed steps wait at least this long so signals follow the `Notify` reply.
const MIN_SIGNAL_DELAY_MS: u64 = 5;

pub struct Config {
    pub script: Script,
    pub capabilities: Vec<String>,
    pub server_name: String,
}

#[derive(Default)]
struct State {
    next_id: u32,
    known: HashSet<u32>,
    new_count: usize,
    pending: HashSet<u32>,
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
    id: u32,
    action: StepAction,
    delay_ms: u64,
) {
    sleep(Duration::from_millis(delay_ms.max(MIN_SIGNAL_DELAY_MS))).await;
    // Claim the step; CloseNotification removes it first when it wins the race.
    if !shared.state().pending.remove(&id) {
        return;
    }
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
            emit_closed(&shared, &conn, id, REASON_DISMISSED, "script").await;
        }
        StepAction::Close => {
            emit_closed(&shared, &conn, id, REASON_DISMISSED, "script").await;
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
        let (id, step) = {
            let mut st = shared.state();
            let is_new = replaces_id == 0 || !st.known.contains(&replaces_id);
            let id = if replaces_id == 0 {
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
                st.pending.insert(id);
            }
            (id, step)
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
            actions,
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
            tokio::spawn(run_step(
                Arc::clone(shared),
                conn.clone(),
                id,
                step.action.clone(),
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
        if shared.state().pending.remove(&id) {
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
        (
            self.shared.config.server_name.clone(),
            "passless".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
            "1.2".to_string(),
        )
    }
}
