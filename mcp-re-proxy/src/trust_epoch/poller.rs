//! The trust-epoch poller body: the supervised loop that drives a
//! [`TrustEpochSource`](super::TrustEpochSource) on a cadence.

use std::time::Duration;

use super::EpochReader;
use super::TrustEpochSource;

/// Missed poll rounds tolerated before a source calls itself unhealthy. A poll that
/// is merely late — a scheduling delay, a slow read inside its own timeout — must not
/// read as a dead poller.
const TRUST_EPOCH_MISSED_POLLS_TOLERATED: u64 = 3;

/// The body of the trust-epoch poller: poll `source` on a cadence until `stop` says to
/// finish. Returns the work; it does NOT start a thread.
///
/// The caller spawns it through whatever owns its lifetime, so a process-lifetime poller
/// cannot be started by a module that has no way to stop it (ADR-MCPRE-056 §9). Handing
/// back a body rather than taking the owner as a parameter keeps this module free of the
/// runtime's internal lifecycle types.
///
/// The poller is what keeps the blocking store read off the request path (see
/// [`TrustEpochSource::poll_once`]). An immediate first poll establishes the baseline
/// before serving, so the first advance after startup is detected rather than adopted.
///
/// SUPERVISED, because everything downstream believes what this thread last wrote: the
/// source requires a poll within a bound before calling itself healthy, and EITHER exit —
/// panicked or stopped — reports that nothing will detect another advance.
///
/// The liveness bound is registered HERE, before the body is handed back, so a caller
/// that takes the body and never runs it leaves the source failing closed rather than
/// reporting a health it has no poller to earn.
pub fn trust_epoch_poller_body<R: EpochReader + Send + Sync + 'static>(
    source: std::sync::Arc<TrustEpochSource<R>>,
    interval_secs: u64,
    stop: impl Fn() -> bool + Send + 'static,
) -> impl FnOnce() + Send + 'static {
    source.require_polling_within(Duration::from_secs(
        interval_secs
            .max(1)
            .saturating_mul(TRUST_EPOCH_MISSED_POLLS_TOLERATED)
            // The read itself is bounded, and a poll that is out reading has not
            // fallen behind; allow for one full read on top of the missed rounds.
            .saturating_add(interval_secs.max(1)),
    ));
    let poller = std::sync::Arc::clone(&source);
    move || {
        let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            poller.poll_once();
            // Nap in small increments so a stop is observed within one increment rather
            // than after a whole interval.
            let ticks = interval_secs.saturating_mul(20).max(1); // 20 * 50ms = 1s
            loop {
                for _ in 0..ticks {
                    if stop() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                poller.poll_once();
            }
        }));
        // `ran.is_ok()` here means the loop returned because `stop()` said so.
        let _ = ran;
        source.report_poller_gone();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::super::EpochReadError;
    use super::super::EpochState;
    use super::*;
    use crate::trust_plane::InvalidationChannel;
    use crate::trust_plane::InvalidationEvent;

    /// An in-memory reader whose counter and read count stay reachable from the test
    /// while the source owns the reader.
    struct SharedReader {
        epoch: std::sync::Arc<std::sync::atomic::AtomicI64>,
        reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl SharedReader {
        fn new(initial: i64) -> Self {
            SharedReader {
                epoch: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(initial)),
                reads: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }
    }
    impl EpochReader for SharedReader {
        fn read_state(&self) -> Result<EpochState, EpochReadError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(EpochState {
                counter: self.epoch.load(std::sync::atomic::Ordering::SeqCst),
                generation: None,
            })
        }
    }

    /// Wait until `done` holds, or fail after `within`. Polling rather than sleeping a
    /// fixed amount, so the bound asserted is the one the property names.
    fn wait_for(within: Duration, mut done: impl FnMut() -> bool) -> Duration {
        let started = Instant::now();
        while !done() {
            assert!(
                started.elapsed() <= within,
                "condition not met within {within:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        started.elapsed()
    }

    /// The production poller, not `poll_once` driven by hand: the FIRST read happens at
    /// once, the next reads happen on the cadence, and a stop is observed inside it.
    ///
    /// This is the only test that runs `trust_epoch_poller_body`, and it is the one that
    /// makes the startup line true. Every other test drives `poll_once` directly, which
    /// proves what a poll does and nothing about whether one happens: a body that slept a
    /// full interval before its first read, or never read again after it, would leave
    /// every other control in this module green while the replica adopted the first
    /// advance after startup as its baseline and detected nothing afterwards.
    #[test]
    fn the_poller_body_reads_at_once_then_on_its_cadence_and_stops_when_asked() {
        let reader = SharedReader::new(1);
        let reads = std::sync::Arc::clone(&reader.reads);
        let epoch = std::sync::Arc::clone(&reader.epoch);
        let src = std::sync::Arc::new(TrustEpochSource::new(reader));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let halt = std::sync::Arc::clone(&stop);
        let body = trust_epoch_poller_body(std::sync::Arc::clone(&src), 1, move || {
            halt.load(std::sync::atomic::Ordering::SeqCst)
        });
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            body();
            let _ = finished_tx.send(());
        });

        // Immediate first poll: the baseline exists well before one interval has passed.
        let first = wait_for(Duration::from_millis(500), || {
            reads.load(std::sync::atomic::Ordering::SeqCst) >= 1
        });
        assert!(
            first < Duration::from_secs(1),
            "the first read waited an interval"
        );
        assert!(
            src.is_healthy(),
            "a polled source under its poller reports healthy"
        );
        assert!(
            src.drain_pending().is_empty(),
            "the baseline poll must not flush"
        );

        // An advance is detected within one interval of the cadence, plus scheduling.
        epoch.store(2, std::sync::atomic::Ordering::SeqCst);
        let detected = wait_for(Duration::from_millis(2_500), || {
            src.drain_pending() == vec![InvalidationEvent::FlushAll]
        });
        assert!(
            detected <= Duration::from_millis(2_500),
            "the flush landed later than one poll interval plus slack: {detected:?}"
        );

        // The stop is observed inside the interval, not at its end.
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the poller stops within its nap increments, not after a full interval");
    }

    /// A reader whose SECOND read panics: the first establishes a baseline, then the
    /// poller dies inside its own thread.
    struct PanicsOnSecondRead {
        reads: std::sync::atomic::AtomicUsize,
    }
    impl EpochReader for PanicsOnSecondRead {
        fn read_epoch(&self) -> Result<i64, EpochReadError> {
            let n = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert!(n == 0, "the poller's read panicked");
            Ok(1)
        }
        fn read_state(&self) -> Result<EpochState, EpochReadError> {
            self.read_epoch().map(|counter| EpochState {
                counter,
                generation: None,
            })
        }
    }

    /// A poller that dies takes the health claim with it.
    ///
    /// Everything downstream believes what this thread last wrote. Unsupervised, a panic
    /// leaves `healthy` latched at `true` and `last_poll` at a recent instant, so the
    /// replica keeps reporting a revocation window it no longer provides until the
    /// liveness bound expires — and the bound is several intervals long. The supervisor
    /// reports the death at once instead.
    #[test]
    fn a_poller_whose_read_panics_reports_the_source_unhealthy_at_once() {
        let src = std::sync::Arc::new(TrustEpochSource::new(PanicsOnSecondRead {
            reads: std::sync::atomic::AtomicUsize::new(0),
        }));
        let body = trust_epoch_poller_body(std::sync::Arc::clone(&src), 1, || false);
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        // Quiet the panic message: the panic is the test's input, not a failure of it.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        std::thread::spawn(move || {
            body();
            let _ = finished_tx.send(());
        });
        finished_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("the body returns after the panic instead of taking the thread down");
        std::panic::set_hook(previous);
        assert!(
            !src.is_healthy(),
            "a dead poller must not keep reporting the health it last observed"
        );
    }

    /// T6. A poller asked to STOP reports unhealthy at once, not when the bound expires.
    ///
    /// The other half of the same fact, and the one that was missing: only the panic exit
    /// reported, so after a graceful stop `is_healthy()` stayed true for the whole
    /// missed-poll tolerance — several intervals — while nothing was driving the source.
    ///
    /// The tolerance is set to a minute here on purpose. Under the old code this test
    /// passes only by waiting that minute out, so a pass now is a statement about the exit
    /// path rather than about how long the test was willing to sleep.
    #[test]
    fn a_gracefully_stopped_poller_reports_unhealthy_at_once() {
        let src = std::sync::Arc::new(TrustEpochSource::new(SharedReader::new(1)));
        let stop_after_first_nap = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = std::sync::Arc::clone(&stop_after_first_nap);
        let body = trust_epoch_poller_body(std::sync::Arc::clone(&src), 60, move || {
            stop.load(std::sync::atomic::Ordering::SeqCst)
        });
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            body();
            let _ = finished_tx.send(());
        });

        // The first poll has landed and the liveness bound is a minute wide, so nothing
        // but the stop path can make this go false in the next three seconds.
        wait_for(Duration::from_secs(3), || src.is_healthy());
        stop_after_first_nap.store(true, std::sync::atomic::Ordering::SeqCst);
        finished_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("the body returns when asked to stop");
        let _ = handle.join();

        assert!(
            !src.is_healthy(),
            "a stopped poller detects no more advances than a dead one, so it must not keep \
             reporting the health it last observed"
        );
    }
}
