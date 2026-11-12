//! Coalescing of refusal audit records (ADR 0014 sections 9 and 12; final security review M2).
//!
//! Every refusal before a reservation is a `policy.deny` record, and every record is fsynced. A web
//! page can loop `navigator.credentials.get()` for an unlisted RP and make one refusal per call, so
//! an unbounded stream of records would exhaust the audit disk and put the audit gate (and with it
//! every agent) into the degraded state. The ledger bounds that stream without losing a refusal:
//!
//! - refusals are keyed by `(session, RP ID, action, reason)`; the ledger lives in the session, so
//!   the session is part of every key;
//! - the first [`FULL_RECORDS_PER_WINDOW`] refusals of a key in a window of [`REFUSAL_WINDOW`] are
//!   written in full, as before;
//! - the rest are counted. The count is written as one `policy.deny` summary record with its
//!   `suppressed` field set: when the window ends and the key is refused again, whenever the count
//!   reaches [`SUMMARY_EVERY`], and, at the latest, when the session ends (revoked or dropped);
//! - a session tracks at most [`MAX_KEYS_PER_SESSION`] keys. A key beyond it is counted under one
//!   shared overflow key per `(action, reason)`, whose summary names the RP as `unknown`, so
//!   rotating RP IDs does not defeat the bound.
//!
//! A suppressed refusal is therefore never lost: it is counted and the count is written. The one
//! gap is a daemon that is killed while a count is pending (fewer than [`SUMMARY_EVERY`] refusals
//! per key); a clean exit that drops the session writes it. A revoked session stays in the
//! registry's tombstone ring after its flush, so a late use of its bearer is still audited; the
//! registry sweeps those ledgers ([`RefusalLedger::flush_due`]), which writes a pending count one
//! window after the key's first refusal without waiting for another one. A live session's counts
//! wait for its end as described above. Served duplicates keep their own cap
//! ([`super::session::MAX_AUDITED_SERVES_PER_KEY`]) and do not pass through the ledger.
//!
//! Locking (`LOCKING.md`): the ledger's mutex is a leaf at [`LockLevel::RefusalLedger`], below the
//! audit gate. Only counters change under it; every record is written after it is released.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::warn;

use super::audit::AuditGate;
use super::audit_events::{AuditAction, OperationRecord, PolicyDenyBuilder, PolicyDenyReason};
use super::lock_order::{self, LockLevel};

use passless_core::agent::ProfileId;

/// Refusals of one key written in full per window.
pub const FULL_RECORDS_PER_WINDOW: u32 = 16;
/// How long a key's window lasts. The next refusal after it ends writes the pending summary and
/// starts a new window.
pub const REFUSAL_WINDOW: Duration = Duration::from_secs(60);
/// A key whose suppressed count reaches this writes its summary at once, inside the window, so a
/// pending count stays small and a flood still writes a bounded number of records.
pub const SUMMARY_EVERY: u64 = 1024;
/// Keys one session tracks; refusals beyond it share an overflow key per `(action, reason)`.
pub const MAX_KEYS_PER_SESSION: usize = 64;
/// The RP the summary of the shared overflow key names.
const OVERFLOW_RP_ID: &str = "unknown";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefusalKey {
    action: AuditAction,
    rp_id: String,
    reason: PolicyDenyReason,
}

impl RefusalKey {
    pub fn new(action: AuditAction, rp_id: &str, reason: PolicyDenyReason) -> Self {
        Self {
            action,
            rp_id: rp_id.to_string(),
            reason,
        }
    }

    fn overflow(&self) -> Self {
        Self::new(self.action, OVERFLOW_RP_ID, self.reason)
    }
}

/// What a summary record is built from: the most recent suppressed refusal's operation fields (its
/// origin context cleared, since a summary may span several origins).
pub struct SummaryTemplate {
    pub gate: Arc<AuditGate>,
    pub profile_id: ProfileId,
    pub op: OperationRecord,
}

struct Entry {
    window_start: Instant,
    /// Records written in full in this window.
    written: u32,
    /// Refusals counted but not written since the last summary.
    suppressed: u64,
    template: Option<(SummaryTemplate, String)>,
}

/// A pending count, ready to be written as one `policy.deny` record.
pub struct Summary {
    template: SummaryTemplate,
    key: RefusalKey,
    rp_id: String,
    count: u64,
}

impl Summary {
    /// The number of refusals this summary accounts for.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Write the summary record. A failed write is logged: the audit gate is then broken, which
    /// degrades agent support until an administrator repairs it (ADR 0014 section 12).
    pub fn write(self) {
        let event = PolicyDenyBuilder::new(
            self.template.profile_id.clone(),
            self.key.action,
            &self.rp_id,
            self.key.reason,
        )
        .operation(self.template.op.with_rp_id(&self.rp_id))
        .suppressed(self.count)
        .build();
        if let Err(e) = self.template.gate.record(event) {
            warn!(
                "agent audit: a summary of {} refusal(s) could not be written: {}",
                self.count, e
            );
        }
    }
}

/// What to do with one refusal.
pub struct Admission {
    /// Write this refusal as a full `policy.deny` record.
    pub write_in_full: bool,
    /// Summaries that became due; write them before the refusal's own record.
    pub summaries: Vec<Summary>,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<RefusalKey, Entry>,
}

impl Entry {
    fn take_summary(&mut self, key: &RefusalKey) -> Option<Summary> {
        if self.suppressed == 0 {
            return None;
        }
        let (template, rp_id) = self.template.take()?;
        let count = std::mem::take(&mut self.suppressed);
        Some(Summary {
            template,
            key: key.clone(),
            rp_id,
            count,
        })
    }
}

impl Inner {
    /// Make room for `key` when the table is full: a key whose window ended is flushed and
    /// dropped. Returns whether `key` can be tracked on its own.
    fn make_room(&mut self, key: &RefusalKey, now: Instant, summaries: &mut Vec<Summary>) -> bool {
        if self.entries.contains_key(key) || self.entries.len() < MAX_KEYS_PER_SESSION {
            return true;
        }
        let ended: Vec<RefusalKey> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                now.saturating_duration_since(entry.window_start) >= REFUSAL_WINDOW
            })
            .map(|(key, _)| key.clone())
            .collect();
        for ended_key in ended {
            if let Some(mut entry) = self.entries.remove(&ended_key) {
                summaries.extend(entry.take_summary(&ended_key));
            }
        }
        self.entries.len() < MAX_KEYS_PER_SESSION
    }
}

/// The refusal ledger of one session. See the module documentation.
#[derive(Default)]
pub struct RefusalLedger {
    inner: Mutex<Inner>,
}

impl RefusalLedger {
    /// Account for one refusal of `key` at `now`. `template` builds the summary template and runs
    /// only when the refusal is suppressed, under the ledger's mutex (atomics only).
    pub fn admit(
        &self,
        key: RefusalKey,
        now: Instant,
        template: impl FnOnce() -> SummaryTemplate,
    ) -> Admission {
        let mut summaries = Vec::new();
        let write_in_full = {
            let mut inner = lock_order::lock(&self.inner, LockLevel::RefusalLedger);
            let key = if inner.make_room(&key, now, &mut summaries) {
                key
            } else {
                key.overflow()
            };
            // The overflow key itself is always trackable: at most one per (action, reason).
            let entry = inner.entries.entry(key.clone()).or_insert_with(|| Entry {
                window_start: now,
                written: 0,
                suppressed: 0,
                template: None,
            });
            if now.saturating_duration_since(entry.window_start) >= REFUSAL_WINDOW {
                summaries.extend(entry.take_summary(&key));
                entry.window_start = now;
                entry.written = 0;
            }
            if entry.written < FULL_RECORDS_PER_WINDOW {
                entry.written += 1;
                true
            } else {
                entry.suppressed += 1;
                entry.template = Some((template(), key.rp_id.clone()));
                if entry.suppressed >= SUMMARY_EVERY {
                    summaries.extend(entry.take_summary(&key));
                }
                false
            }
        };
        Admission {
            write_in_full,
            summaries,
        }
    }

    /// Take every pending count (the session ended). The caller writes them.
    pub fn drain(&self) -> Vec<Summary> {
        let mut inner = lock_order::lock(&self.inner, LockLevel::RefusalLedger);
        let mut summaries = Vec::new();
        for (key, entry) in inner.entries.iter_mut() {
            summaries.extend(entry.take_summary(key));
        }
        summaries
    }

    /// Write every pending count now (a revoked session, or a drop).
    pub fn flush(&self) {
        for summary in self.drain() {
            summary.write();
        }
    }

    /// Take the pending counts of every key whose window has ended at `now`. A revoked session is
    /// kept in the tombstone ring to audit late use of its bearer, and `revoke` has already
    /// flushed it, so a refusal counted after that would wait for another refusal of the same key
    /// or for the session's eviction. The registry sweeps its tombstones with this instead
    /// (`SignContextRegistry::flush_due_revoked_refusals`), so a pending count is written within
    /// one window and one sweep interval of its refusal, with no further refusal needed. A key
    /// refused again later starts a new window as usual.
    pub fn drain_due(&self, now: Instant) -> Vec<Summary> {
        let mut inner = lock_order::lock(&self.inner, LockLevel::RefusalLedger);
        let mut summaries = Vec::new();
        for (key, entry) in inner.entries.iter_mut() {
            if now.saturating_duration_since(entry.window_start) >= REFUSAL_WINDOW {
                summaries.extend(entry.take_summary(key));
            }
        }
        summaries
    }

    /// Write the counts [`Self::drain_due`] takes.
    pub fn flush_due(&self, now: Instant) {
        for summary in self.drain_due(now) {
            summary.write();
        }
    }

    /// Refusals counted and not yet written, over every key (tests and diagnostics).
    #[cfg(test)]
    pub fn pending(&self) -> u64 {
        lock_order::lock(&self.inner, LockLevel::RefusalLedger)
            .entries
            .values()
            .map(|entry| entry.suppressed)
            .sum()
    }

    /// Keys currently tracked (tests).
    #[cfg(test)]
    pub fn tracked_keys(&self) -> usize {
        lock_order::lock(&self.inner, LockLevel::RefusalLedger)
            .entries
            .len()
    }
}

impl Drop for RefusalLedger {
    /// A session that ends still owes the counts it holds: write them, so no refusal is lost to a
    /// clean exit.
    fn drop(&mut self) {
        let inner = std::mem::take(
            self.inner
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let mut entries = inner.entries;
        for (key, entry) in entries.iter_mut() {
            if let Some(summary) = entry.take_summary(key) {
                summary.write();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agent::audit::test_support::read_audit_events;

    struct Rig {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
        gate: Arc<AuditGate>,
        ledger: RefusalLedger,
    }

    impl Rig {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("audit");
            let gate = Arc::new(AuditGate::open(&path).unwrap());
            Self {
                _dir: dir,
                path,
                gate,
                ledger: RefusalLedger::default(),
            }
        }

        /// What `CeremonyAudit::deny` does for one refusal.
        fn refuse(&self, rp_id: &str, reason: PolicyDenyReason, now: Instant) {
            let profile = ProfileId::new("test-profile").unwrap();
            let op = OperationRecord::new(profile.clone(), AuditAction::Authenticate, rp_id)
                .origin_context(Some("https://page.test"), None, Some(false));
            let admission = self.ledger.admit(
                RefusalKey::new(AuditAction::Authenticate, rp_id, reason),
                now,
                || SummaryTemplate {
                    gate: self.gate.clone(),
                    profile_id: profile.clone(),
                    op: op.clone().origin_context(None, None, None),
                },
            );
            for summary in admission.summaries {
                summary.write();
            }
            if admission.write_in_full {
                let event =
                    PolicyDenyBuilder::new(profile, AuditAction::Authenticate, rp_id, reason)
                        .operation(op)
                        .build();
                self.gate.record(event).unwrap();
            }
        }

        fn denies(&self) -> Vec<serde_json::Value> {
            read_audit_events(&self.path)
                .into_iter()
                .filter(|e| e["kind"] == "policy.deny")
                .collect()
        }
    }

    /// Refusals accounted for by the records: each full record is one, a summary is its count.
    fn accounted(records: &[serde_json::Value]) -> u64 {
        records
            .iter()
            .map(|r| r["suppressed"].as_u64().unwrap_or(1))
            .sum()
    }

    #[test]
    fn the_first_refusals_are_written_in_full_and_the_rest_are_counted() {
        let rig = Rig::new();
        let now = Instant::now();
        for _ in 0..1000 {
            rig.refuse("unlisted.example", PolicyDenyReason::DefaultDeny, now);
        }
        let written = rig.denies();
        assert_eq!(written.len(), FULL_RECORDS_PER_WINDOW as usize);
        assert!(written.iter().all(|r| r["suppressed"].is_null()));
        assert_eq!(
            rig.ledger.pending(),
            1000 - u64::from(FULL_RECORDS_PER_WINDOW)
        );

        // The pending count is written when the session ends, and nothing is lost.
        rig.ledger.flush();
        let written = rig.denies();
        assert_eq!(written.len(), FULL_RECORDS_PER_WINDOW as usize + 1);
        let summary = written.last().unwrap();
        assert_eq!(
            summary["suppressed"],
            1000 - u64::from(FULL_RECORDS_PER_WINDOW)
        );
        assert_eq!(summary["reason"], "default_deny");
        assert_eq!(summary["rp_id"], "unlisted.example");
        assert_eq!(summary["action"], "authenticate");
        assert!(summary["origin"].is_null(), "a summary names no origin");
        assert_eq!(accounted(&written), 1000);
        assert_eq!(rig.ledger.pending(), 0);
    }

    /// Review L5: a count that waits after the session's flush is written when its window ends,
    /// without another refusal of the key.
    #[test]
    fn a_sweep_writes_a_pending_count_once_its_window_has_ended() {
        let rig = Rig::new();
        let start = Instant::now();
        for _ in 0..(u64::from(FULL_RECORDS_PER_WINDOW) + 5) {
            rig.refuse("unlisted.example", PolicyDenyReason::BearerRevoked, start);
        }
        assert_eq!(rig.ledger.pending(), 5);

        // Inside the window nothing is due.
        rig.ledger
            .flush_due(start + REFUSAL_WINDOW - Duration::from_secs(1));
        assert_eq!(rig.ledger.pending(), 5);
        assert_eq!(rig.denies().len(), FULL_RECORDS_PER_WINDOW as usize);

        // At the window's end the summary is written, once.
        rig.ledger.flush_due(start + REFUSAL_WINDOW);
        rig.ledger.flush_due(start + REFUSAL_WINDOW * 2);
        let written = rig.denies();
        assert_eq!(written.len(), FULL_RECORDS_PER_WINDOW as usize + 1);
        assert_eq!(written.last().unwrap()["suppressed"], 5);
        assert_eq!(rig.ledger.pending(), 0);
        assert_eq!(accounted(&written), u64::from(FULL_RECORDS_PER_WINDOW) + 5);
    }

    #[test]
    fn keys_are_independent_per_rp_and_reason() {
        let rig = Rig::new();
        let now = Instant::now();
        for rp in ["a.example", "b.example"] {
            for reason in [
                PolicyDenyReason::DefaultDeny,
                PolicyDenyReason::OriginInvalid,
            ] {
                for _ in 0..FULL_RECORDS_PER_WINDOW {
                    rig.refuse(rp, reason, now);
                }
            }
        }
        // Every key got its own full records: nothing was suppressed.
        assert_eq!(rig.denies().len(), 4 * FULL_RECORDS_PER_WINDOW as usize);
        assert_eq!(rig.ledger.pending(), 0);
    }

    #[test]
    fn a_new_window_writes_the_pending_summary_and_full_records_again() {
        let rig = Rig::new();
        let start = Instant::now();
        for _ in 0..40 {
            rig.refuse("a.example", PolicyDenyReason::DefaultDeny, start);
        }
        let later = start + REFUSAL_WINDOW + Duration::from_secs(1);
        rig.refuse("a.example", PolicyDenyReason::DefaultDeny, later);
        let written = rig.denies();
        // 16 in full, the summary of the 24 suppressed, then the first of the new window.
        assert_eq!(written.len(), 16 + 1 + 1);
        assert_eq!(written[16]["suppressed"], 24);
        assert!(written[17]["suppressed"].is_null());
        assert_eq!(rig.ledger.pending(), 0);
        assert_eq!(accounted(&written), 41);
    }

    #[test]
    fn a_pending_count_reaching_the_bound_is_written_inside_the_window() {
        let rig = Rig::new();
        let now = Instant::now();
        let total = u64::from(FULL_RECORDS_PER_WINDOW) + SUMMARY_EVERY * 2 + 5;
        for _ in 0..total {
            rig.refuse("a.example", PolicyDenyReason::DefaultDeny, now);
        }
        let written = rig.denies();
        // 16 in full and two summaries of SUMMARY_EVERY; five are still pending.
        assert_eq!(written.len(), 16 + 2);
        assert_eq!(written[16]["suppressed"], SUMMARY_EVERY);
        assert_eq!(written[17]["suppressed"], SUMMARY_EVERY);
        assert_eq!(rig.ledger.pending(), 5);
        rig.ledger.flush();
        assert_eq!(accounted(&rig.denies()), total);
    }

    #[test]
    fn rotating_rp_ids_cannot_defeat_the_bound() {
        let rig = Rig::new();
        let now = Instant::now();
        // Far more distinct RPs than the session tracks.
        let rps = MAX_KEYS_PER_SESSION * 40;
        for n in 0..rps {
            rig.refuse(
                &format!("rp{n}.example"),
                PolicyDenyReason::DefaultDeny,
                now,
            );
        }
        // Tracked keys stay bounded (the shared overflow key is one more).
        assert!(rig.ledger.tracked_keys() <= MAX_KEYS_PER_SESSION + 1);
        rig.ledger.flush();
        let written = rig.denies();
        // The records written are bounded by the keys' full allowances, not by the requests.
        assert!(
            written.len() <= (MAX_KEYS_PER_SESSION + 1) * FULL_RECORDS_PER_WINDOW as usize + 1,
            "{} records for {rps} refusals",
            written.len()
        );
        assert!(written.len() < rps);
        // Every refusal is accounted for, and the overflow summary names the RP `unknown`.
        assert_eq!(accounted(&written), rps as u64);
        assert!(
            written
                .iter()
                .any(|r| !r["suppressed"].is_null() && r["rp_id"] == "unknown")
        );
    }

    #[test]
    fn dropping_the_ledger_writes_what_is_pending() {
        let rig = Rig::new();
        let now = Instant::now();
        for _ in 0..30 {
            rig.refuse("a.example", PolicyDenyReason::DefaultDeny, now);
        }
        let Rig {
            _dir,
            path,
            gate,
            ledger,
        } = rig;
        drop(ledger);
        let written: Vec<_> = read_audit_events(&path)
            .into_iter()
            .filter(|e| e["kind"] == "policy.deny")
            .collect();
        assert_eq!(accounted(&written), 30);
        drop(gate);
    }
}
