//! Issue #4028 — live cross-node replay proof against a REAL Redis.
//!
//! This whole file is compiled ONLY under the `redis_replay` feature (the same
//! feature that compiles the [`RedisAsyncAtomicReplayStore`]). It is a BLACK-BOX
//! exercise of the store's public `AsyncAtomicReplayStore` API over two stores with
//! independent connections to the SAME Redis — modelling two proxy nodes sharing one
//! backend.
//!
//! Redis is not installed in every environment, so the test is gated on the
//! `MCP_RE_TEST_REDIS_URL` env var: when it is unset the test prints a skip notice
//! and returns successfully (it does NOT fail). When it is set (e.g. in a CI job
//! that brings up Redis), it runs the load-bearing assertion: a nonce accepted on
//! node A is rejected as a replay on node B.
#![cfg(feature = "redis_replay")]

mod harness;
mod topology;

use mcp_re_core::ReplayDecision;
use mcp_re_proxy::shared_replay::ReplayStoreError;

use harness::{
    composite_key, connect_pool, count, expires_soon, insert_concurrently, now_unix, raw_conn,
    redis_url, replica_admin_url, runtime, skip, Missing, Node, Nonce, Signer,
};
use topology::{primary_connected_slaves, Topology};

/// The load-bearing cross-node proof: a nonce accepted on node A is rejected as a
/// replay on node B, where A and B are two separate stores over two separate
/// connections to the SAME Redis. This is the property the single-node file cache
/// cannot provide.
#[test]
fn cross_node_insert_via_a_is_replay_via_b() {
    let Some(url) = redis_url() else {
        skip("cross_node_insert_via_a_is_replay_via_b", Missing::Redis);
        return;
    };

    let signer = &Signer::for_test("cross_node_insert_via_a_is_replay_via_b");
    let nonce = &Nonce::fresh();

    let rt = runtime();
    let node_a = Node::connect(&rt, &url);
    let node_b = Node::connect(&rt, &url);

    assert_eq!(
        node_a.insert(signer, nonce, expires_soon()),
        Ok(ReplayDecision::Fresh),
        "first sight on node A must be Fresh"
    );
    assert_eq!(
        node_b.insert(signer, nonce, expires_soon()),
        Ok(ReplayDecision::Replay),
        "node B must reject a nonce first seen on node A — shared Redis replay state"
    );
}

/// Single-node fresh-then-replay over the real Redis: the same node sees a nonce
/// once as Fresh and again as Replay.
#[test]
fn single_node_fresh_then_replay() {
    let Some(url) = redis_url() else {
        skip("single_node_fresh_then_replay", Missing::Redis);
        return;
    };

    let signer = &Signer::for_test("single_node_fresh_then_replay");
    let nonce = &Nonce::fresh();

    let rt = runtime();
    let node = Node::connect(&rt, &url);
    assert_eq!(
        node.insert(signer, nonce, expires_soon()),
        Ok(ReplayDecision::Fresh),
        "first sight is Fresh"
    );
    assert_eq!(
        node.insert(signer, nonce, expires_soon()),
        Ok(ReplayDecision::Replay),
        "second sight on the same node is a Replay"
    );
}

/// The largest admitted replay pool admits a nonce exactly once. Concurrent inserts of
/// ONE key spread round-robin over 128 connections must yield one `Fresh` and every other
/// a `Replay`, and distinct keys must all be `Fresh`: which connection an insert takes
/// never changes its decision, so `--replay-redis-pool-size` moves throughput and nothing
/// the replay tier decides.
#[test]
fn a_maximal_pool_admits_each_nonce_exactly_once_under_concurrent_duplicates() {
    let Some(url) = redis_url() else {
        skip(
            "a_maximal_pool_admits_each_nonce_exactly_once_under_concurrent_duplicates",
            Missing::Redis,
        );
        return;
    };
    let signer = &Signer::for_test("pooled-exactly-once");
    let rt = runtime();
    let store = connect_pool(&rt, &url, None, 128);
    let retain_until = expires_soon();
    let fresh_key = || composite_key(signer, &Nonce::fresh());
    let duplicate = fresh_key();
    let dup = insert_concurrently(&rt, &store, vec![duplicate; 256], retain_until);
    let fresh = insert_concurrently(
        &rt,
        &store,
        (0..256).map(|_| fresh_key()).collect(),
        retain_until,
    );
    assert_eq!(
        count(&dup, &ReplayDecision::Fresh),
        1,
        "one key is admitted once"
    );
    assert_eq!(
        count(&dup, &ReplayDecision::Replay),
        255,
        "every other sight is a replay"
    );
    assert_eq!(
        count(&fresh, &ReplayDecision::Fresh),
        256,
        "distinct nonces are all fresh"
    );
}

/// MCPS-090 / H-8 / H-9 — live PTTL confirmation that the inserted key gets a
/// BOUNDED `retain_until - now` window TTL, NOT the `now = 0` absolute-epoch TTL
/// (~1.78e9 s × 1000 ≈ 56 years) that let the keyspace grow without bound.
///
/// We pick a retain-until a fixed offset into the future from the REAL system clock
/// so the expected window is well-defined regardless of wall-clock, insert, then read
/// `PTTL` on the exact key inserted. The TTL must be within a small band around
/// `(retain_until - now)`, and MUST be far below the absolute-epoch range. Gated on
/// `MCP_RE_TEST_REDIS_URL` exactly like the other live tests — SKIP is printed and the
/// test passes (never silently a pass of a real assertion) when no Redis is present.
#[test]
fn live_pttl_is_bounded_window_not_absolute_epoch() {
    let Some(url) = redis_url() else {
        skip(
            "live_pttl_is_bounded_window_not_absolute_epoch",
            Missing::Redis,
        );
        return;
    };

    let signer = &Signer::for_test("live_pttl_is_bounded_window_not_absolute_epoch");
    let nonce = &Nonce::fresh();

    // A window of ~600s from the REAL clock: retain_until = now + 600.
    let window_secs: i64 = 600;
    let retain_until = now_unix() + window_secs;

    let rt = runtime();
    let node = Node::connect(&rt, &url);
    assert_eq!(
        node.insert(signer, nonce, retain_until),
        Ok(ReplayDecision::Fresh),
        "first sight is Fresh"
    );

    // Probe PTTL on the exact key inserted.
    let key = composite_key(signer, nonce);
    let mut conn = raw_conn(&url);
    let pttl_ms: i64 = redis::cmd("PTTL")
        .arg(&key)
        .query(&mut conn)
        .expect("PTTL query");

    // Expected window in ms is (retain_until - now) * 1000. Allow a generous band for
    // the seconds the op itself took.
    let expected_ms = window_secs * 1000;
    assert!(
        pttl_ms > 0,
        "key must carry a positive TTL, got PTTL={pttl_ms} (key missing or no expiry)"
    );
    assert!(
        (pttl_ms - expected_ms).abs() < 60_000,
        "PTTL ({pttl_ms} ms) must be ≈ the (retain_until - now) window ({expected_ms} ms), \
         within 60s"
    );
    // The decisive anti-regression bound: the now=0 bug would set PTTL on the
    // order of retain_until * 1000 (~1.78e12 ms). The window is < 0.1% of that.
    let absolute_epoch_ms = retain_until.saturating_mul(1000);
    assert!(
        pttl_ms < absolute_epoch_ms / 1000,
        "PTTL ({pttl_ms} ms) must be vastly below the now=0 absolute-epoch TTL \
         ({absolute_epoch_ms} ms ≈ 56 years)"
    );
}

// ---------------------------------------------------------------------------
// Issue #41 — distributed proof of the ADR-MCPS-020 Amendment-1 WAIT-quorum
// shortfall contract against a REAL primary + replica Redis.
//
// The lane (#39 workflow) provisions a primary on 6379 and a replica on 6380
// (`--replicaof 127.0.0.1 6379`). MCP_RE_TEST_REDIS_URL points at the primary;
// MCP_RE_TEST_REDIS_REPLICA_URL is the replica's own connection, used ONLY to
// drive `REPLICAOF` so the test can induce a real WAIT-quorum shortfall and a
// recovery deterministically (no container stop/start, no blind sleeps).
// ---------------------------------------------------------------------------

/// WAIT timeout for the quorum insert: short enough to keep the test snappy, long
/// enough not to flake under CI load (a shortfall costs exactly this once).
const WAIT_TIMEOUT_MS: u64 = 1_500;

/// The Amendment-1 distributed proof, on the store the serving path builds: against a
/// real primary+replica Redis, prove (1) a healthy replica-acked WAIT-quorum insert is
/// `Fresh`; (2) detaching the replica induces a genuine WAIT shortfall that fails
/// closed as `ReplayStoreError::Unavailable`, never `Fresh`; (3) a same-nonce retry after the
/// shortfall is NOT `Fresh` (keep-the-nonce); (4) reattaching + resyncing the
/// replica restores `Fresh` for a new nonce.
#[test]
fn wait_quorum_shortfall_and_recovery_against_a_replica() {
    let (Some(primary_url), Some(replica_url)) = (redis_url(), replica_admin_url()) else {
        skip(
            "wait_quorum_shortfall_and_recovery_against_a_replica",
            Missing::ReplicaTopology,
        );
        return;
    };

    let mut topology = Topology::open(&primary_url, &replica_url);

    // A future expiry so the inserted key carries a real multi-second TTL window
    // and persists across the phases below (a past expiry would clamp to ~1ms and
    // vanish between calls). Test-name-derived signer plus a per-run suffix for a key
    // space of this run's own (see `signer_for`).
    let signer = &Signer::for_test("wait_quorum_shortfall_and_recovery");
    let expires_at = now_unix() + 600;

    // Ensure a clean starting topology: replica attached + link up + visible.
    topology.attach();

    let rt = runtime();
    let node = Node::connect_with_wait_quorum(&rt, &primary_url, WAIT_TIMEOUT_MS);

    // (1) Healthy: WAIT 1 is satisfied by the attached replica → Fresh.
    assert_eq!(
        node.insert(signer, &Nonce::fresh(), expires_at),
        Ok(ReplayDecision::Fresh),
        "a replica-acked WAIT-quorum insert must be Fresh"
    );

    // (2) Shortfall: detach the replica, confirm the primary sees zero replicas,
    //     then a fresh insert's WAIT 1 cannot be met → fail closed, never Fresh.
    topology.detach();

    let shortfall_nonce = Nonce::fresh();
    let shortfall = node.insert(signer, &shortfall_nonce, expires_at);
    assert!(
        matches!(shortfall, Err(ReplayStoreError::Unavailable { .. })),
        "a WAIT-quorum shortfall must fail closed as ReplayStoreError::Unavailable, got {shortfall:?}"
    );
    assert_ne!(
        shortfall,
        Ok(ReplayDecision::Fresh),
        "a WAIT-quorum shortfall must NEVER be reported as Fresh"
    );

    // (3) Same-nonce retry after the shortfall: the SET NX landed on the primary,
    //     so the nonce is burned — the retry must NOT be Fresh (Replay or another
    //     fail-closed are both acceptable per Amendment 1; Fresh is not).
    let retry = node.insert(signer, &shortfall_nonce, expires_at);
    assert_ne!(
        retry,
        Ok(ReplayDecision::Fresh),
        "the same nonce after a shortfall must not be retryable as Fresh (keep-the-nonce contract); got {retry:?}"
    );

    // (4) Recovery: reattach + resync the replica, then a NEW nonce is Fresh again.
    topology.reattach();
    assert_eq!(
        node.insert(signer, &Nonce::fresh(), expires_at),
        Ok(ReplayDecision::Fresh),
        "after replica reattach + resync, a fresh nonce must be Fresh again"
    );
}

/// The Amendment-1 shortfall on a POOLED store, without touching the topology: a quorum
/// one above the replicas the primary has attached cannot be met, so every fresh insert
/// spread round-robin over 32 connections fails closed as `Unavailable`, none is
/// `Fresh`, and a same-nonce retry is not `Fresh` either. The control half — a quorum
/// equal to the attached replicas on an identical pool admits — shows the shortfall is
/// the only difference. A larger `--replay-redis-pool-size` adds connections that run
/// the same tier; it gives an unmet quorum no connection to succeed on.
#[test]
fn a_pooled_store_fails_closed_on_every_connection_when_the_quorum_cannot_be_met() {
    let Some(url) = redis_url() else {
        skip(
            "a_pooled_store_fails_closed_on_every_connection_when_the_quorum_cannot_be_met",
            Missing::Redis,
        );
        return;
    };
    let attached = u32::try_from(primary_connected_slaves(&mut raw_conn(&url)).max(0))
        .expect("a replica count fits u32");
    let signer = &Signer::for_test("pooled-shortfall");
    let rt = runtime();
    let pooled = |quorum: u32| connect_pool(&rt, &url, Some((quorum, 300)), 32);
    let retain_until = expires_soon();
    let keys = |n| -> Vec<String> {
        (0..n)
            .map(|_| composite_key(signer, &Nonce::fresh()))
            .collect()
    };

    if attached > 0 {
        let met = insert_concurrently(&rt, &pooled(attached), keys(64), retain_until);
        assert!(
            met.iter().all(|r| *r == Ok(ReplayDecision::Fresh)),
            "a quorum of the {attached} attached replicas admits: {met:?}"
        );
    }

    let unmet = pooled(attached + 1);
    let shortfall_keys = keys(64);
    let shortfall = insert_concurrently(&rt, &unmet, shortfall_keys.clone(), retain_until);
    assert!(
        shortfall
            .iter()
            .all(|r| matches!(r, Err(ReplayStoreError::Unavailable { .. }))),
        "WAIT {} against {attached} replicas fails closed on every connection: {shortfall:?}",
        attached + 1
    );
    let retry = insert_concurrently(&rt, &unmet, shortfall_keys, retain_until);
    assert!(
        retry.iter().all(|r| *r != Ok(ReplayDecision::Fresh)),
        "a nonce burned by a shortfall is never Fresh on retry: {retry:?}"
    );
}
