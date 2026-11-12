//! TPM context creation helper

use std::sync::{Mutex, MutexGuard};

use log::warn;
use tss_esapi::constants::CapabilityType;
use tss_esapi::constants::tss::TPM2_TRANSIENT_FIRST;
use tss_esapi::handles::TpmHandle;
use tss_esapi::structures::CapabilityData;
use tss_esapi::{Context, Tcti};

/// Create a TPM context from an optional TCTI configuration string.
///
/// If `tcti` is `Some(s)`, parses `s` as a TCTI configuration.
/// If `tcti` is `None`, uses the default TCTI (device:/dev/tpmrm0).
///
/// Returns the raw `tss_esapi::Error` so callers can map to their own error types
/// and add their own log messages.
pub(crate) fn create_tpm_context(
    tcti: Option<&str>,
) -> core::result::Result<Context, tss_esapi::Error> {
    let tcti_conf = match tcti {
        Some(s) => std::str::FromStr::from_str(s)?,
        None => Tcti::Device(Default::default()),
    };
    Context::new(tcti_conf)
}

/// Lock a TPM context, recovering a lock poisoned by a panic.
///
/// A panic inside `tss-esapi` (or in code that runs with the context held) poisons the mutex.
/// Without recovery every later human TPM operation would fail for the rest of the daemon's life,
/// which breaks ADR 0014 invariant 23. Recovering is sound because the context is reusable after
/// a failed call: it holds an ESYS connection and a handle table, not a half-written credential,
/// and the TPM is never left in a state that a new command cannot start from. What an unwound
/// call can leave behind is state in the context:
///
/// - Transient objects it had loaded (a primary key, a sealed object) and did not flush. They
///   occupy a TPM slot until flushed. [`flush_transient_handles`] flushes them on recovery, on a
///   best-effort basis (a failure is logged and the next command is attempted anyway).
/// - Session settings (`set_sessions`) the panicking call had installed. They are cleared, so the
///   next call sets its own.
///
/// Every operation that uses the context creates the handles it needs inside the call and flushes
/// them before it returns, so nothing the adapters keep across calls is affected by the flush.
/// Credential files are written by renaming a complete temporary file, so no stored credential
/// is half-written either.
pub(crate) fn lock_context(context: &Mutex<Context>) -> MutexGuard<'_, Context> {
    lock_recovering(context, "TPM context", flush_transient_handles)
}

/// Lock `mutex`, and when it is poisoned clear the poison and run `repair` on the value.
fn lock_recovering<'a, T>(
    mutex: &'a Mutex<T>,
    what: &str,
    repair: impl FnOnce(&mut T),
) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        warn!("{what} lock was poisoned by a panicked thread; recovering");
        mutex.clear_poison();
        let mut guard = poisoned.into_inner();
        repair(&mut guard);
        guard
    })
}

/// How many `TPM2_GetCapability` rounds the recovery makes at most.
const MAX_FLUSH_ROUNDS: usize = 4;
/// Handles asked for per round.
const FLUSH_BATCH: u32 = 32;

/// Clear the session settings of `context` and flush every transient object loaded in the TPM
/// behind it. See [`lock_context`] for why this is safe: no adapter keeps a transient handle
/// across calls, and a hardware TPM reached through the kernel resource manager
/// (`/dev/tpmrm0`) only lists this connection's own objects.
fn flush_transient_handles(context: &mut Context) {
    context.clear_sessions();
    for _ in 0..MAX_FLUSH_ROUNDS {
        let (data, more) = match context.get_capability(
            CapabilityType::Handles,
            TPM2_TRANSIENT_FIRST,
            FLUSH_BATCH,
        ) {
            Ok(result) => result,
            Err(e) => {
                warn!("could not list transient TPM handles after a panic: {e}");
                return;
            }
        };
        let CapabilityData::Handles(list) = data else {
            return;
        };
        let handles = list.into_inner();
        if handles.is_empty() {
            return;
        }
        for handle in handles {
            if !matches!(handle, TpmHandle::Transient(_)) {
                continue;
            }
            match context.tr_from_tpm_public(handle) {
                Ok(object) => {
                    if let Err(e) = context.flush_context(object) {
                        warn!("could not flush a transient TPM handle after a panic: {e}");
                    }
                }
                Err(e) => warn!("could not open a transient TPM handle after a panic: {e}"),
            }
        }
        if !more {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    #[test]
    fn a_poisoned_lock_is_recovered_repaired_and_unpoisoned() {
        let mutex = Arc::new(Mutex::new(vec![1u8]));
        let poisoner = mutex.clone();
        let result = std::thread::spawn(move || {
            let mut guard = poisoner.lock().unwrap();
            guard.push(2);
            panic!("simulated tss-esapi panic");
        })
        .join();
        assert!(result.is_err());
        assert!(mutex.is_poisoned());

        let mut repaired = false;
        {
            let guard = lock_recovering(&mutex, "test", |value: &mut Vec<u8>| {
                repaired = true;
                value.clear();
            });
            assert!(guard.is_empty(), "repair ran on the recovered value");
        }
        assert!(repaired);
        assert!(!mutex.is_poisoned());

        // A healthy lock is returned as it is, with no repair.
        let guard = lock_recovering(&mutex, "test", |_| panic!("no repair expected"));
        assert!(guard.is_empty());
    }
}
