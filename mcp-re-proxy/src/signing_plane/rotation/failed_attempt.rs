// SPDX-License-Identifier: Apache-2.0
//! A rotation attempt that adopted nothing: recorded, scheduled and waited out in one place.
//!
//! The failure counter, the remaining validity and the backoff are read together because the
//! backoff is a function of the other two. Recording the failure is what makes the count
//! the schedule reads, so the two cannot be separated by a caller that forgets one.

use std::time::Duration;

use crate::clock::now_unix;
use crate::delegated_server_signer::{rotation_backoff, DelegatedServerSigner};
use crate::managed_worker::Halt;

use super::super::rotation_jitter;

/// One failure, already counted, with the interval the schedule says to wait.
pub(in crate::signing_plane) struct FailedAttempt {
    /// Failures since the last success, this one included.
    pub(in crate::signing_plane) consecutive_failures: u32,
    /// Seconds the current key stays valid, `None` when no key is published.
    pub(in crate::signing_plane) time_to_expiry: Option<i64>,
    /// How long to wait before approaching the root again.
    pub(in crate::signing_plane) backoff: Duration,
}

impl FailedAttempt {
    /// Count a failure and read the schedule's answer for it.
    pub(in crate::signing_plane) fn record(signer: &DelegatedServerSigner) -> Self {
        let consecutive_failures = signer.metrics().record_failure();
        let time_to_expiry = signer.seconds_to_expiry(now_unix());
        let backoff = rotation_backoff(consecutive_failures, time_to_expiry, rotation_jitter);
        Self {
            consecutive_failures,
            time_to_expiry,
            backoff,
        }
    }

    /// Wait out the backoff. `None` when a halt interrupted it, otherwise the failure count
    /// the next pass starts from.
    pub(in crate::signing_plane) fn wait(&self, halt: &Halt) -> Option<u32> {
        if halt.sleep(self.backoff) {
            None
        } else {
            Some(self.consecutive_failures)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_worker::WorkerSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn wait_carries_the_recorded_failure_count_when_not_halted() {
        let workers = WorkerSet::new(Arc::new(AtomicBool::new(false)));
        let attempt = FailedAttempt {
            consecutive_failures: 3,
            time_to_expiry: None,
            backoff: Duration::from_millis(1),
        };
        assert_eq!(attempt.wait(&workers.halt()), Some(3));
    }

    #[test]
    fn wait_reports_a_halt_instead_of_a_count() {
        let deployment = Arc::new(AtomicBool::new(false));
        let halt = WorkerSet::new(Arc::clone(&deployment)).halt();
        deployment.store(true, Ordering::SeqCst);
        let attempt = FailedAttempt {
            consecutive_failures: 3,
            time_to_expiry: None,
            backoff: Duration::from_secs(60),
        };
        assert_eq!(attempt.wait(&halt), None);
    }

    #[test]
    fn recording_counts_the_failure_exactly_once_and_reports_that_count() {
        let signer = DelegatedServerSigner::new();
        let first = FailedAttempt::record(&signer);
        assert_eq!(first.consecutive_failures, 1);
        assert_eq!(signer.metrics().consecutive_failures(), 1);
        let second = FailedAttempt::record(&signer);
        assert_eq!(second.consecutive_failures, 2);
        assert_eq!(signer.metrics().consecutive_failures(), 2);
        assert_eq!(second.time_to_expiry, None, "no key is published");
    }
}
