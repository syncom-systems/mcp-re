//! `SharedReplayCache` wrapper coherence (single-threaded, deterministic).

use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayTriple;
use mcp_re_proxy::config_state::FreshnessWindow;
use mcp_re_proxy::InMemoryAtomicReplayStore;
use mcp_re_proxy::SharedReplayCache;

use super::support::FAR_FUTURE_RETAIN_UNTIL;

/// The deployment window a wrapper cache retains under.
fn window(skew_secs: i64) -> FreshnessWindow {
    FreshnessWindow::new(skew_secs).expect("bounded")
}

/// A replica over `backend` retaining under the 30-second window.
fn replica_over(backend: &InMemoryAtomicReplayStore) -> SharedReplayCache {
    SharedReplayCache::new(Box::new(backend.clone()), window(30))
}

/// Submit `nonce` for the fixed `(signer, audience)` pair through `cache`.
fn submit(cache: &SharedReplayCache, nonce: &str) -> ReplayDecision {
    cache
        .check_and_insert(
            ReplayTriple::new("did:example:agent", "did:example:server", nonce),
            FAR_FUTURE_RETAIN_UNTIL,
        )
        .expect("the in-memory tier is available")
}

/// The `SharedReplayCache` composite-key + skew-folding path admits the first
/// submission of a `(signer, audience, nonce)` and rejects the second — the
/// pure wrapper over the authoritative tier the race exercises concurrently.
#[test]
fn shared_cache_first_is_fresh_then_replay() {
    let cache = replica_over(&InMemoryAtomicReplayStore::new());
    let nonce = mcp_re_test_paths::unique_test_nonce();
    assert_eq!(submit(&cache, &nonce), ReplayDecision::Fresh);
    assert_eq!(submit(&cache, &nonce), ReplayDecision::Replay);
    // A different nonce is independently Fresh.
    assert_eq!(
        submit(&cache, &mcp_re_test_paths::unique_test_nonce()),
        ReplayDecision::Fresh
    );
}

/// Cross-replica coherence at the wrapper level: two `SharedReplayCache`
/// replicas over ONE shared backend — a nonce admitted (`Fresh`) via replica A
/// is `Replay` via replica B, because the authoritative tier is shared. This is
/// the store-shared analogue of the fleet Redis proof (MCPS-81), on the default
/// in-memory backend.
#[test]
fn shared_cache_cross_replica_admit_via_a_is_replay_via_b() {
    let backend = InMemoryAtomicReplayStore::new();
    let replica_a = replica_over(&backend);
    let replica_b = replica_over(&backend);
    let nonce = mcp_re_test_paths::unique_test_nonce();

    assert_eq!(
        submit(&replica_a, &nonce),
        ReplayDecision::Fresh,
        "replica A admits the fresh nonce",
    );
    assert_eq!(
        submit(&replica_b, &nonce),
        ReplayDecision::Replay,
        "replica B rejects it as a replay — the authoritative tier is shared",
    );
}
