//! The poll-based invalidation source over an [`EpochReader`], and the one lock policy
//! its mutexes share.

use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;

use super::EpochReader;
use super::EpochState;
use crate::trust_plane::InvalidationChannel;
use crate::trust_plane::InvalidationEvent;

/// Take a lock, recovering it if a panic elsewhere poisoned it.
///
/// What these mutexes guard is a queue of pending invalidations, the last epoch this
/// node saw, and two liveness readings — none of which a panic can leave in a state
/// that is unsafe to read. Treating poison as a failure instead drops an operator's
/// revocation on the floor permanently and silently, because the queue is the only
/// path a `FlushAll` has to the trust cache.
pub(super) fn recover<'a, T>(
    lock: Result<MutexGuard<'a, T>, PoisonError<MutexGuard<'a, T>>>,
) -> MutexGuard<'a, T> {
    lock.unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A poll-based, self-healing [`InvalidationChannel`] over an [`EpochReader`].
///
/// On each `drain_pending` it reads the epoch and emits a coarse
/// [`InvalidationEvent::FlushAll`] iff the epoch differs from the last value this
/// node saw (an advance — or, defensively, any change, since a monotonic counter
/// only moves forward and a decrease would mean a store reset that also warrants a
/// flush). The FIRST successful poll only establishes the baseline (no spurious
/// startup flush). A read error marks the source unhealthy and emits nothing.
pub struct TrustEpochSource<R: EpochReader> {
    reader: R,
    last_seen: Mutex<Option<EpochState>>,
    healthy: Mutex<bool>,
    /// Events produced by [`poll_once`](TrustEpochSource::poll_once) and not yet
    /// drained. This is what keeps the store read OFF the request path.
    pending: Mutex<Vec<InvalidationEvent>>,
    /// When [`poll_once`](TrustEpochSource::poll_once) last ran to completion.
    last_poll: Mutex<Option<Instant>>,
    /// How long this source may go unpolled before it stops calling itself healthy.
    /// `None` when no poller was spawned over it (a directly-driven source has no
    /// cadence to fall behind).
    liveness_bound: Mutex<Option<Duration>>,
}

impl<R: EpochReader> TrustEpochSource<R> {
    /// A fresh source over `reader`, healthy until the first failed read, with no
    /// baseline yet (the first successful poll establishes it).
    pub fn new(reader: R) -> Self {
        TrustEpochSource {
            reader,
            last_seen: Mutex::new(None),
            healthy: Mutex::new(true),
            pending: Mutex::new(Vec::new()),
            last_poll: Mutex::new(None),
            liveness_bound: Mutex::new(None),
        }
    }

    /// Require a poll within `bound`, now that [`trust_epoch_poller_body`] owns producing one.
    pub(super) fn require_polling_within(&self, bound: Duration) {
        *recover(self.liveness_bound.lock()) = Some(bound);
    }

    /// Whether this source has been polled recently enough for `healthy` to still
    /// describe it.
    ///
    /// `healthy` is a latch that only `poll_once` writes, so a poller that has stopped
    /// running — a panic, a thread that never started, a wedged read — leaves it at
    /// whatever it last said, which is `true` for every replica that was working when
    /// it stopped. That replica would keep asserting a one-poll-interval revocation
    /// window it no longer provides, and an operator's advance would never reach its
    /// trust cache. Silence past the bound is therefore unhealthy on its own.
    fn polled_recently(&self) -> bool {
        let Some(bound) = *recover(self.liveness_bound.lock()) else {
            return true;
        };
        match *recover(self.last_poll.lock()) {
            Some(at) => at.elapsed() <= bound,
            // A poller is expected but has not produced its first poll yet: there is no
            // baseline, so there is no invalidation guarantee to claim.
            None => false,
        }
    }

    /// Record that nothing is driving this source any more, so `healthy` stops describing
    /// one that is.
    pub(super) fn report_poller_gone(&self) {
        *recover(self.healthy.lock()) = false;
        *recover(self.last_poll.lock()) = None;
        eprintln!(
            "mcp-re-proxy: WARNING: the trust-epoch poller thread has stopped; this replica no \
             longer detects epoch advances and now reports its push tier UNHEALTHY, which \
             reverts the surfaced guarantee to the bounded-T trust-cache TTL."
        );
    }

    /// Latch `healthy` to `now` and announce the transition; a repeat of the current
    /// state is silent, so a seconds-cadence poll logs once per outage, not per poll.
    fn set_healthy(&self, now: bool, cause: &str) -> bool {
        let changed = std::mem::replace(&mut *recover(self.healthy.lock()), now) != now;
        let effect = if now { "recovered" } else { "tier UNHEALTHY" };
        if changed {
            eprintln!("mcp-re-proxy: WARNING: trust-epoch health changed ({cause}): {effect}.");
        }
        changed
    }

    /// Read the epoch ONCE and queue a [`InvalidationEvent::FlushAll`] if it moved.
    ///
    /// **Called from a background poller, never from the request path.** The read is a
    /// blocking network round trip behind a single connection mutex; keeping it off
    /// the request path means a half-open store cannot stall the per-core runtimes and
    /// an unauthenticated peer cannot force reads by replaying a `keyid`.
    ///
    /// Polling on a cadence changes the honest guarantee from "flush on the next
    /// request after an advance" to "flush within one poll interval", which is what
    /// the startup line now says.
    pub fn poll_once(&self) {
        // Recorded whatever the read says: this timestamp is proof the POLLER is
        // running, which is a different question from whether the STORE answered.
        *recover(self.last_poll.lock()) = Some(Instant::now());
        let epoch = match self.reader.read_state() {
            Ok(e) => e,
            Err(e) => {
                // Fail closed without advancing the baseline, so an outage-time
                // change is caught on recovery.
                self.set_healthy(false, &e.0);
                return;
            }
        };
        self.set_healthy(true, "the epoch read succeeded");
        let mut last = recover(self.last_seen.lock());
        match *last {
            None => {
                // First poll: establish the baseline, emit nothing.
                *last = Some(epoch);
            }
            Some(ref prev) if epoch != *prev => {
                // The queue push and the baseline advance have to happen together:
                // advancing without queueing loses the flush permanently, since the
                // next poll sees no further change.
                recover(self.pending.lock()).push(InvalidationEvent::FlushAll);
                *last = Some(epoch);
            }
            Some(_) => {}
        }
    }
}

impl<R: EpochReader> InvalidationChannel for TrustEpochSource<R> {
    /// Take whatever the background poller has queued. NO I/O: this is on the request
    /// path (`PushInvalidationTrustCache::resolve` calls it before every lookup), so
    /// it must cost a mutex acquisition and nothing more.
    fn drain_pending(&self) -> Vec<InvalidationEvent> {
        std::mem::take(&mut *recover(self.pending.lock()))
    }

    /// Healthy means BOTH that the last read succeeded and that a read is still
    /// happening: a latch nothing writes any more says only what was true when the
    /// poller was last alive.
    fn is_healthy(&self) -> bool {
        self.polled_recently() && *recover(self.healthy.lock())
    }
}

#[cfg(test)]
mod tests {
    use super::super::EpochReadError;
    use super::*;
    use crate::trust_epoch::SharedEpochChannel;

    /// A scriptable in-memory epoch reader: `Some(n)` reads epoch `n`, `None`
    /// simulates a read failure.
    struct FakeReader {
        epoch: Mutex<Option<i64>>,
        /// The generation an advance last wrote beside the counter.
        generation: Mutex<Option<String>>,
        /// Counts reads, so a test can assert the REQUEST path performs none.
        reads: std::sync::atomic::AtomicUsize,
    }
    impl FakeReader {
        fn new(initial: i64) -> Self {
            FakeReader {
                epoch: Mutex::new(Some(initial)),
                generation: Mutex::new(None),
                reads: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn set(&self, epoch: i64) {
            *self.epoch.lock().unwrap() = Some(epoch);
        }
        fn fail(&self) {
            *self.epoch.lock().unwrap() = None;
        }
        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    impl EpochReader for FakeReader {
        fn read_epoch(&self) -> Result<i64, EpochReadError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match *self.epoch.lock().unwrap() {
                Some(e) => Ok(e),
                None => Err(EpochReadError("fake reader down".into())),
            }
        }
        fn read_state(&self) -> Result<EpochState, EpochReadError> {
            Ok(EpochState {
                counter: self.read_epoch()?,
                generation: self.generation.lock().unwrap().clone(),
            })
        }
    }

    #[test]
    fn first_poll_establishes_baseline_without_flush() {
        let src = TrustEpochSource::new(FakeReader::new(7));
        src.poll_once();
        assert!(
            src.drain_pending().is_empty(),
            "baseline poll must not flush"
        );
        assert!(src.is_healthy());
        // A steady epoch on the next poll is still no flush.
        src.poll_once();
        assert!(src.drain_pending().is_empty());
    }

    #[test]
    fn epoch_advance_emits_a_single_flush_all() {
        // The test submodule can reach the private `reader` field to script epochs.
        // `poll_once` is the READ (background thread); `drain_pending` is the queue
        // the request path takes and does no I/O of its own.
        let src = TrustEpochSource::new(FakeReader::new(1));
        src.poll_once();
        assert!(src.drain_pending().is_empty()); // baseline @1
                                                 // Advance the epoch and poll: exactly one FlushAll.
        src.reader.set(2);
        src.poll_once();
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
        // No further flush while the epoch is steady.
        src.poll_once();
        assert!(src.drain_pending().is_empty());
        // A second advance flushes again.
        src.reader.set(5);
        src.poll_once();
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
    }

    /// A store rolled back between polls and then advanced back onto the counter this node
    /// last saw still flushes: the advance wrote a fresh generation, and the counter alone
    /// would have hidden it.
    #[test]
    fn an_advance_onto_an_already_seen_counter_still_flushes() {
        let src = TrustEpochSource::new(FakeReader::new(10));
        *src.reader.generation.lock().unwrap() = Some("g-before".into());
        src.poll_once();
        assert!(src.drain_pending().is_empty());
        // Rolled back to 9 and advanced to 10 again, both between two polls.
        *src.reader.generation.lock().unwrap() = Some("g-after".into());
        src.poll_once();
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
        // The same counter under the same generation is no change.
        src.poll_once();
        assert!(src.drain_pending().is_empty());
    }

    /// The property the poller exists for: draining costs NO store read. Inline, this
    /// was a blocking Redis round trip on every served request, serialized fleet-wide
    /// behind one connection mutex and reached before signature verification.
    #[test]
    fn draining_does_not_read_the_store() {
        let src = TrustEpochSource::new(FakeReader::new(1));
        src.poll_once();
        let before = src.reader.reads();
        for _ in 0..100 {
            let _ = src.drain_pending();
        }
        assert_eq!(
            src.reader.reads(),
            before,
            "the request path must not touch the store"
        );
    }

    #[test]
    fn a_trust_epoch_outage_is_announced_on_its_edges_not_per_poll() {
        let src = TrustEpochSource::new(FakeReader::new(3));
        src.poll_once();
        src.reader.fail();
        src.poll_once();
        assert!(
            !src.set_healthy(false, "probe"),
            "poll_once latched the edge"
        );
        assert!(src.set_healthy(true, "probe"));
        assert!(!src.set_healthy(true, "probe"));
    }

    #[test]
    fn read_error_marks_unhealthy_and_emits_nothing() {
        let src = TrustEpochSource::new(FakeReader::new(3));
        src.poll_once();
        assert!(src.drain_pending().is_empty()); // baseline @3
        src.reader.fail();
        src.poll_once();
        assert!(
            src.drain_pending().is_empty(),
            "a read error emits no events"
        );
        assert!(!src.is_healthy(), "a read error marks the source unhealthy");
    }

    /// `healthy` is a latch only `poll_once` writes, so a source nothing polls any
    /// more keeps reporting whatever was true when its poller was last alive — which
    /// is `true` for every replica that was working when the thread died. The replica
    /// then asserts a revocation guarantee (`channel_is_healthy`, the startup posture
    /// line) that it no longer provides.
    #[test]
    fn a_source_that_stops_being_polled_stops_reporting_healthy() {
        let src = TrustEpochSource::new(FakeReader::new(1));
        src.require_polling_within(std::time::Duration::from_millis(40));
        src.poll_once();
        assert!(src.is_healthy(), "a freshly polled source is healthy");
        // Nothing polls it again.
        std::thread::sleep(std::time::Duration::from_millis(90));
        assert!(
            !src.is_healthy(),
            "silence past the bound is unhealthy on its own"
        );
        // And it recovers the moment polling resumes.
        src.poll_once();
        assert!(src.is_healthy());
    }

    /// A source under a poller that has not produced its first read has no baseline,
    /// so it has no invalidation guarantee to claim either.
    #[test]
    fn a_poller_that_never_ran_is_not_healthy() {
        let src = TrustEpochSource::new(FakeReader::new(1));
        src.require_polling_within(std::time::Duration::from_secs(60));
        assert!(!src.is_healthy());
    }

    /// A source nobody spawned a poller over is driven directly, so it has no cadence
    /// to fall behind and the liveness bound must not apply to it.
    #[test]
    fn a_directly_driven_source_is_not_subject_to_the_liveness_bound() {
        let src = TrustEpochSource::new(FakeReader::new(1));
        src.poll_once();
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(src.is_healthy());
    }

    /// A poisoned queue used to swallow the FlushAll silently — `poll_once` skipped
    /// the push, `drain_pending` returned an empty vec forever, and neither touched
    /// `healthy`. The operator's advance then never reached this node's trust cache.
    #[test]
    fn a_poisoned_queue_still_delivers_the_flush() {
        let src = std::sync::Arc::new(TrustEpochSource::new(FakeReader::new(1)));
        src.poll_once(); // baseline @1
        let poisoner = std::sync::Arc::clone(&src);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.pending.lock().expect("first acquisition");
            panic!("poison the queue");
        })
        .join();

        src.reader.set(2);
        src.poll_once();
        assert_eq!(
            src.drain_pending(),
            vec![InvalidationEvent::FlushAll],
            "a revocation must not be lost because a lock is poisoned"
        );
    }

    #[test]
    fn recovery_after_outage_catches_an_epoch_that_advanced_during_it() {
        // Self-healing: the baseline is NOT advanced during the outage, so a change
        // that happened while the source was down is detected on the first good poll.
        let src = TrustEpochSource::new(FakeReader::new(10));
        src.poll_once();
        assert!(src.drain_pending().is_empty()); // baseline @10
        src.reader.fail();
        src.poll_once();
        assert!(src.drain_pending().is_empty());
        assert!(!src.is_healthy());
        // The epoch advanced to 12 while we were blind; recovery detects it.
        src.reader.set(12);
        src.poll_once();
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
        assert!(src.is_healthy(), "a successful read restores health");
    }

    /// A reader that PARKS inside `read_epoch`, so a test can hold the poller in the
    /// middle of its network round trip and drive the request path meanwhile.
    struct StalledReader {
        entered: std::sync::mpsc::SyncSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl EpochReader for StalledReader {
        fn read_epoch(&self) -> Result<i64, EpochReadError> {
            // Announce that the "network call" has begun, then block in it.
            let _ = self.entered.send(());
            let _ = recover(self.release.lock()).recv();
            Ok(1)
        }
        fn read_state(&self) -> Result<EpochState, EpochReadError> {
            self.read_epoch().map(|counter| EpochState {
                counter,
                generation: None,
            })
        }
    }

    /// The request path does not wait on the epoch reader's network round trip.
    ///
    /// This is the executable form of the claim in `trust_plane`: "the whole per-core
    /// fleet is not serialized on one Redis connection". `PushInvalidationTrustCache`
    /// calls `drain_pending` before every lookup, so if that call could ever wait on a
    /// Redis read, one stalled connection would serialize every request on the core —
    /// the failure mode this design exists to avoid.
    ///
    /// Written because the implementation could be "simplified" into exactly that bug:
    /// take the pending mutex, then read the network under it. The result still LOOKS
    /// like background polling — same threads, same function names — and every existing
    /// test still passes, because none of them holds a read open while touching the
    /// request path. This one does.
    ///
    /// A violation would BLOCK rather than assert, so the drain runs on its own thread
    /// and the test fails on a timeout instead of hanging the suite.
    #[test]
    fn the_request_path_does_not_wait_on_a_stalled_epoch_read() {
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let src = std::sync::Arc::new(TrustEpochSource::new(StalledReader {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }));

        let poller = std::sync::Arc::clone(&src);
        let polling = std::thread::spawn(move || poller.poll_once());

        // The poller is now INSIDE the blocking read and cannot leave until released.
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the poller reaches the read");

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let requester = std::sync::Arc::clone(&src);
        std::thread::spawn(move || {
            // Exactly what the resolver does before every lookup.
            let events = requester.drain_pending();
            let _ = done_tx.send(events.len());
        });

        let served = done_rx.recv_timeout(Duration::from_secs(5));
        assert!(
            served.is_ok(),
            "drain_pending blocked while the epoch read was stalled: the request path is \
             serialized on the reader's connection"
        );

        // Only now let the read finish, proving the drain above genuinely overlapped it.
        let _ = release_tx.send(());
        polling.join().expect("poller thread joins");
    }

    /// A counter that goes BACKWARDS is a change, and a change flushes.
    ///
    /// The source has no notion of rollback to represent: it compares the read against the
    /// last value it saw and flushes on any difference. That is the only safe reading of a
    /// regression — a store restored from a snapshot, a failover to a replica that never
    /// saw the advance, a reconnect landing on the wrong instance — because a flush can only
    /// tighten trust. Adopting the lower value silently would be the one thing the
    /// request-side reader must never do: skip the flush the operator's advance had earned
    /// and wait for the counter to climb back past it.
    #[test]
    fn a_regressed_counter_flushes_rather_than_being_adopted_silently() {
        let src = TrustEpochSource::new(FakeReader::new(5));
        src.poll_once();
        assert!(src.drain_pending().is_empty()); // baseline @5
        src.reader.set(3);
        src.poll_once();
        assert_eq!(
            src.drain_pending(),
            vec![InvalidationEvent::FlushAll],
            "a regressed counter is a change the cache must hear about"
        );
        assert!(src.is_healthy(), "a regression is not a read failure");
        // The lower value is now the baseline, so climbing back is a change too — the
        // source never remembers a high-water mark, and must not: that is the signing
        // side's rule, where minting under a lower epoch would resurrect credentials.
        src.reader.set(5);
        src.poll_once();
        assert_eq!(src.drain_pending(), vec![InvalidationEvent::FlushAll]);
    }

    /// A store the composition test scripts: `Ok(key)` or `Err(Revoked)`, counting how
    /// often the cache actually consulted it.
    struct ScriptedStore {
        revoked: std::sync::atomic::AtomicBool,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl mcp_re_core::TrustResolver for ScriptedStore {
        fn resolve(
            &self,
            _signer: &str,
            _key_id: &str,
        ) -> Result<mcp_re_core::VerificationKey, mcp_re_core::TrustResolverError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(mcp_re_core::TrustResolverError::Revoked);
            }
            Ok(mcp_re_core::SigningKey::from_seed_bytes(&[5u8; 32]).public_key())
        }
    }

    /// The push-tier cache over THIS source, with a store and a clock the test drives.
    ///
    /// `push_trust`'s own tests drive an in-memory channel, and this module's tests drive
    /// the source with nothing behind it; the property a deployment relies on is the two
    /// composed, which only the Redis-gated e2e exercised. Wired exactly as
    /// `build_trust_epoch_channel` wires it: a `SharedEpochChannel` over one shared source.
    fn push_cache_over(
        src: &std::sync::Arc<TrustEpochSource<FakeReader>>,
        store: std::sync::Arc<ScriptedStore>,
        clock: std::sync::Arc<std::sync::atomic::AtomicI64>,
    ) -> crate::trust_plane::PushInvalidationTrustCache {
        struct Shared(std::sync::Arc<ScriptedStore>);
        impl mcp_re_core::TrustResolver for Shared {
            fn resolve(
                &self,
                signer: &str,
                key_id: &str,
            ) -> Result<mcp_re_core::VerificationKey, mcp_re_core::TrustResolverError> {
                self.0.resolve(signer, key_id)
            }
        }
        crate::trust_plane::PushInvalidationTrustCache::new(
            Box::new(Shared(store)),
            COMPOSED_T,
            5,
            Box::new(move || clock.load(std::sync::atomic::Ordering::SeqCst)),
            Box::new(SharedEpochChannel(std::sync::Arc::clone(src))),
        )
    }

    /// The bounded window the composition tests run under.
    const COMPOSED_T: i64 = 60;

    /// An observed advance strips the cache's authority before the next lookup, so the
    /// next answer is the store's — and, as the negative control, a poll that observes NO
    /// advance leaves the cached answer standing over a store that has already revoked.
    ///
    /// This is the in-process form of what `redis_trust_epoch_e2e_test` shows with a real
    /// store: the same source type, the same cache type, the same channel adapter, minus
    /// the foreign read. What it establishes is a property of ONE replica's reaction to a
    /// value its reader returned; what the counter's value means across replicas is the
    /// store's premise, not this test's.
    #[test]
    fn an_observed_advance_makes_the_next_lookup_the_stores_answer() {
        use mcp_re_core::TrustResolver;
        let src = std::sync::Arc::new(TrustEpochSource::new(FakeReader::new(1)));
        let store = std::sync::Arc::new(ScriptedStore {
            revoked: std::sync::atomic::AtomicBool::new(false),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let clock = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(1_000));
        let cache = push_cache_over(&src, std::sync::Arc::clone(&store), clock);
        src.poll_once(); // baseline @1

        cache.resolve("did:host", "key-1").expect("active cached");
        let calls = || store.calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(calls(), 1);

        // NEGATIVE CONTROL: the store revokes, the counter does not move. The cached
        // binding still answers — nothing on this replica has learned anything.
        store
            .revoked
            .store(true, std::sync::atomic::Ordering::SeqCst);
        src.poll_once();
        cache
            .resolve("did:host", "key-1")
            .expect("without an advance the cached binding serves within T");
        assert_eq!(calls(), 1, "no advance, no re-resolve");

        // The advance is observed. The next lookup is the store's answer.
        src.reader.set(2);
        src.poll_once();
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            mcp_re_core::TrustResolverError::Revoked,
            "after an observed advance the cache answers nothing on its own authority"
        );
        assert_eq!(calls(), 2, "the flush forced exactly one live resolution");
    }

    /// A source outage flushes nothing and changes nothing about serving: the cached
    /// binding stands until its own deadline, and at that deadline the store is consulted
    /// whatever the source says.
    ///
    /// This pins what "reverts to the bounded-T guarantee" MEANS in the tree. The health
    /// flag is a witness nothing on the request path reads; the bound under an outage is
    /// the same deadline the entry carried while the source was healthy. A test that
    /// asserted only `!is_healthy()` would let an implementation serve past T on the
    /// unhealthy arm and stay green.
    #[test]
    fn a_source_outage_flushes_nothing_and_the_deadline_still_governs() {
        use mcp_re_core::TrustResolver;
        let src = std::sync::Arc::new(TrustEpochSource::new(FakeReader::new(1)));
        let store = std::sync::Arc::new(ScriptedStore {
            revoked: std::sync::atomic::AtomicBool::new(false),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let clock = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(1_000));
        let cache = push_cache_over(&src, std::sync::Arc::clone(&store), clock.clone());
        src.poll_once(); // baseline @1
        cache.resolve("did:host", "key-1").expect("active cached");

        // The store revokes AND the counter advances, but the read fails: the advance is
        // invisible to this replica, and it must not guess.
        store
            .revoked
            .store(true, std::sync::atomic::Ordering::SeqCst);
        src.reader.fail();
        src.poll_once();
        assert!(!src.is_healthy());
        clock.store(1_000 + COMPOSED_T - 1, std::sync::atomic::Ordering::SeqCst);
        cache
            .resolve("did:host", "key-1")
            .expect("inside its deadline the cached binding serves through the outage");
        assert_eq!(store.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        // At the deadline the store is consulted, outage or not.
        clock.store(1_000 + COMPOSED_T, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            mcp_re_core::TrustResolverError::Revoked,
            "the deadline governs whatever the source says"
        );

        // Recovery: the read returns, the advance that happened during the outage is
        // caught, and the flush lands — self-healing, through the cache this time.
        src.reader.set(2);
        src.poll_once();
        assert!(src.is_healthy());
        assert_eq!(
            src.drain_pending(),
            vec![InvalidationEvent::FlushAll],
            "the advance missed during the outage is detected on recovery"
        );
    }
}
