//! The async live authoritative tiers (Redis, etcd) raced directly at the store.

use std::sync::Arc;

use mcp_re_core::ReplayDecision;
use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
use mcp_re_proxy::async_replay::ReplayInsert;

use super::live_infra::live_endpoint;
use super::support::multi_thread_runtime;
use super::support::unique_token;
use super::support::FAR_FUTURE_RETAIN_UNTIL;
use super::support::RACE_ROUNDS;
use super::support::RACE_WIDTH;

/// Every entry in this file is charged to one signer; the per-actor budget is
/// exercised by its own test in `async_replay_test.rs`.
const TEST_ACTOR: &str = "did:example:test-signer";

/// A round key namespaced by a per-lane `salt`.
fn salted_round_key(salt: &str, round: usize) -> String {
    format!("did:example:agent\u{1f}did:example:server\u{1f}nonce-{salt}-{round}")
}

/// Fire `RACE_WIDTH` tasks that all submit the SAME `key` to `store`, and count
/// the `Fresh` verdicts.
async fn fresh_in_one_round<S>(store: &Arc<S>, key: &str) -> usize
where
    S: AsyncAtomicReplayStore + 'static,
{
    let handles: Vec<_> = (0..RACE_WIDTH)
        .map(|_| {
            let store = Arc::clone(store);
            let key = key.to_string();
            tokio::spawn(async move {
                store
                    .atomic_insert_if_absent(ReplayInsert::new(
                        &key,
                        TEST_ACTOR,
                        FAR_FUTURE_RETAIN_UNTIL,
                        0,
                    ))
                    .await
            })
        })
        .collect();
    let mut fresh = 0usize;
    for handle in handles {
        if let Ok(ReplayDecision::Fresh) = handle.await.expect("task") {
            fresh += 1;
        }
    }
    fresh
}

/// Race `RACE_ROUNDS` rounds against `store` and assert EXACTLY ONE `Fresh` each.
///
/// The salt is read ONCE so this lane's keys are disjoint from every other lane's
/// on the shared live store, while every task in a round still submits the
/// IDENTICAL key.
async fn assert_exactly_one_fresh_per_round<S>(store: &Arc<S>, lane: &str)
where
    S: AsyncAtomicReplayStore + 'static,
{
    let salt = unique_token();
    for round in 0..RACE_ROUNDS {
        let fresh = fresh_in_one_round(store, &salted_round_key(&salt, round)).await;
        assert_eq!(
            fresh, 1,
            "round {round}: {lane} {RACE_WIDTH}-way race must admit exactly one Fresh"
        );
    }
}

/// ASYNC Redis lane (ADR-MCPRE-051 §4): the async authoritative tier
/// (`RedisAsyncAtomicReplayStore`, `SET NX PX` over the tokio async client) admits
/// EXACTLY ONE `Fresh` under a concurrent race, proven on the async client the
/// per-core data plane awaits.
/// Skip-when-absent (hard-fail under `MCP_RE_REQUIRE_LIVE_INFRA`).
#[cfg(feature = "redis_replay")]
#[test]
fn cross_core_same_key_admits_exactly_one_fresh_redis_async() {
    let Some(url) = live_endpoint("MCP_RE_TEST_REDIS_URL", "async replay-race Redis lane") else {
        return;
    };
    multi_thread_runtime().block_on(async {
        let store = super::live_infra::connect_redis(&url).await;
        assert_exactly_one_fresh_per_round(&store, "async Redis").await;
    });
}

/// ASYNC etcd lane (ADR-MCPRE-051 §4): the CP/linearizable async authoritative tier
/// (`EtcdAsyncAtomicReplayStore`, a `compare { CREATE_REVISION == 0 }` txn over the
/// v3 JSON gateway, AWAITED off the per-core runtime) admits EXACTLY ONE `Fresh`
/// under a concurrent race, on the async client the per-core data plane awaits.
/// Skip-when-absent (hard-fail under `MCP_RE_REQUIRE_LIVE_INFRA`).
#[cfg(feature = "cpstore_etcd")]
#[test]
fn cross_core_same_key_admits_exactly_one_fresh_etcd_async() {
    let Some(endpoint) = live_endpoint("MCP_RE_TEST_ETCD_URL", "async replay-race etcd lane")
    else {
        return;
    };
    multi_thread_runtime().block_on(async {
        let store = super::live_infra::connect_etcd(&endpoint);
        assert_exactly_one_fresh_per_round(&store, "async etcd").await;
    });
}
