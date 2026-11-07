//! The suspension of the refused-credential retry: when a refusal that a FRESH credential did
//! not fix was last observed, and whether the cool-off since has lapsed.

use crate::remote_signer_call::NETWORK_TIMEOUT;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;
use std::time::Instant;

/// How long a refusal that a FRESH credential did not fix suspends the retry.
pub(super) const CREDENTIAL_REFUSAL_RETRY_COOLDOWN: Duration = NETWORK_TIMEOUT;

pub(super) struct Suspension {
    /// When the last refusal that a fresh credential did not fix was observed. `None` in the
    /// steady state. Held as a start rather than an end so no `Instant` arithmetic can overflow.
    since: Mutex<Option<Instant>>,
}

impl Suspension {
    pub(super) fn new() -> Self {
        Self {
            since: Mutex::new(None),
        }
    }

    fn guard(&self) -> MutexGuard<'_, Option<Instant>> {
        self.since.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Is the retry suspended at `now`? Clears a lapsed suspension.
    pub(super) fn holds_at(&self, now: Instant) -> bool {
        let mut since = self.guard();
        match *since {
            Some(start)
                if now.saturating_duration_since(start) < CREDENTIAL_REFUSAL_RETRY_COOLDOWN =>
            {
                true
            }
            Some(_) => {
                *since = None;
                false
            }
            None => false,
        }
    }

    /// Never shortens: a straggler holding an older `now` leaves a later start in place.
    pub(super) fn begin(&self, now: Instant) {
        let mut since = self.guard();
        *since = Some(since.map_or(now, |current| current.max(now)));
    }

    pub(super) fn end(&self) {
        *self.guard() = None;
    }
}
