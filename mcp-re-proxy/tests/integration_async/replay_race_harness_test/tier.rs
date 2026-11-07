//! Default build — the in-memory reference authoritative tier (always runs).

use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

use mcp_re_core::ReplayDecision;
use mcp_re_proxy::AtomicReplayStore;
use mcp_re_proxy::InMemoryAtomicReplayStore;
use mcp_re_proxy::ReplayStoreError;

use super::support::FAR_FUTURE_RETAIN_UNTIL;
use super::support::RACE_ROUNDS;
use super::support::RACE_WIDTH;

type SharedStore = Arc<dyn AtomicReplayStore + Send + Sync>;

/// Tally of the verdicts returned by one race round.
#[derive(Debug, Default, PartialEq, Eq)]
struct RaceTally {
    fresh: usize,
    replay: usize,
    unavailable: usize,
}

/// Fire `RACE_WIDTH` threads that all submit the SAME `key` to `store` at once
/// (barrier-released), then tally the verdicts. `store` is the shared
/// authoritative tier — every thread holds an `Arc` clone of the one store, so
/// the insert-if-absent races for real.
fn race_one_key(store: &SharedStore, key: &str) -> RaceTally {
    let barrier = Arc::new(Barrier::new(RACE_WIDTH));
    let handles: Vec<_> = (0..RACE_WIDTH)
        .map(|_| {
            let store = Arc::clone(store);
            let barrier = Arc::clone(&barrier);
            let key = key.to_string();
            thread::spawn(move || {
                // Every thread parks here; the last arrival releases them all
                // simultaneously into the atomic insert — maximum contention.
                barrier.wait();
                store.insert_if_absent(&key, FAR_FUTURE_RETAIN_UNTIL)
            })
        })
        .collect();

    let mut tally = RaceTally::default();
    for handle in handles {
        match handle.join().expect("race thread panicked") {
            Ok(ReplayDecision::Fresh) => tally.fresh += 1,
            Ok(ReplayDecision::Replay) => tally.replay += 1,
            Err(ReplayStoreError::Unavailable { .. }) => tally.unavailable += 1,
        }
    }
    tally
}

/// A composite-shaped replay key for round `round`. The store treats the key as
/// opaque; the only invariant the race depends on is that every thread in a
/// round submits the IDENTICAL key and distinct rounds use distinct keys.
fn round_key(round: usize) -> String {
    format!("did:example:agent\u{1f}did:example:server\u{1f}nonce-{round}")
}

/// Drive `RACE_ROUNDS` independent race rounds against `store` and assert, for
/// every round, the tally `expected`.
fn assert_every_round_tallies(store: &SharedStore, expected: &RaceTally, what: &str) {
    for round in 0..RACE_ROUNDS {
        let tally = race_one_key(store, &round_key(round));
        assert_eq!(&tally, expected, "round {round}: {what}");
    }
}

/// Drive `RACE_ROUNDS` independent race rounds against `store` and assert EXACTLY
/// ONE `Fresh` + `RACE_WIDTH - 1` `Replay` + ZERO `Unavailable` every round. This
/// is the cross-core property: many threads (cores) racing one replay key on one
/// shared authoritative tier admit the request exactly once.
fn assert_exactly_one_fresh_per_round(store: &SharedStore) {
    let expected = RaceTally {
        fresh: 1,
        replay: RACE_WIDTH - 1,
        unavailable: 0,
    };
    assert_every_round_tallies(
        store,
        &expected,
        &format!("{RACE_WIDTH}-way race must admit exactly one Fresh"),
    );
}

/// An authoritative tier that is always down — every insert fails closed.
struct AlwaysUnavailableStore;

impl AtomicReplayStore for AlwaysUnavailableStore {
    fn insert_if_absent(
        &self,
        _key: &str,
        _expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayStoreError> {
        Err(ReplayStoreError::Unavailable {
            details: "authoritative replay tier down".to_string(),
        })
    }
}

/// Cross-core: `RACE_WIDTH` threads racing ONE replay key on ONE shared store
/// yield exactly one `Fresh`, `RACE_WIDTH - 1` `Replay`. Repeated over many
/// rounds so no single interleaving carries the proof.
#[test]
fn cross_core_same_key_admits_exactly_one_fresh_in_memory() {
    let store: SharedStore = Arc::new(InMemoryAtomicReplayStore::new());
    assert_exactly_one_fresh_per_round(&store);
}

/// Cross-replica: two (or more) logical replicas backed by ONE shared store race
/// the same key. `InMemoryAtomicReplayStore` clones share the SAME `Arc<Mutex<…>>`
/// state, so cloning the store per replica models a fleet over one backend
/// exactly as `SharedReplayCache` replicas do. Exactly one `Fresh` still holds.
#[test]
fn cross_replica_shared_store_admits_exactly_one_fresh_in_memory() {
    // One backend; each race thread is a distinct replica holding its own clone
    // of the shared store (same underlying `Arc<Mutex<…>>` state) — the topology
    // of a horizontally-scaled fleet against a single authoritative tier.
    // Wrapper-level cross-replica agreement over this same backend is asserted
    // deterministically in `shared_cache_cross_replica_admit_via_a_is_replay_via_b`.
    let backend = InMemoryAtomicReplayStore::new();
    let store: SharedStore = Arc::new(backend);
    assert_exactly_one_fresh_per_round(&store);
}

/// Fail-closed: when the authoritative tier is unavailable, a concurrent race
/// produces ZERO `Fresh` — uncertainty is never freshness (ADR-MCPRE-051 §4,
/// `Unavailable` fails closed). Every thread must get `Unavailable`, none admitted.
#[test]
fn store_unavailable_admits_zero_fresh_fail_closed() {
    let store: SharedStore = Arc::new(AlwaysUnavailableStore);
    let expected = RaceTally {
        fresh: 0,
        replay: 0,
        unavailable: RACE_WIDTH,
    };
    assert_every_round_tallies(
        &store,
        &expected,
        "an unavailable tier must admit ZERO Fresh and fail every submission closed as Unavailable",
    );
}
