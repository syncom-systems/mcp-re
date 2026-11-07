//! Full-stack serving path — N concurrent submissions through ONE shared PEP.
//!
//! MCPRE-117 AC. The tier lanes prove the property at the authoritative tier;
//! these prove it end to end on the production serving PEP (`HttpProfileProxy`,
//! ADR-MCPRE-050 sole carrier): N tasks submit the SAME signed RFC 9421 request
//! to ONE shared proxy and EXACTLY ONE is served (200) while the rest are
//! replay-rejected (409). The store behind the tier is the cross-replica
//! coherence boundary, so wiring a live networked store (Redis/etcd) makes this
//! "cross-replica through the full serving path"; `two_replicas_*` wires two
//! independent proxies over ONE live store to state that directly.

mod fixtures;

use std::sync::Arc;

use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::HttpProfileProxy;

use super::support::multi_thread_runtime;
use super::support::unique_token;
use fixtures::now;
use fixtures::proxy_over;
use fixtures::served;
use fixtures::signed_request;

/// How many concurrent submissions of the one nonce each round fires.
const TASKS: usize = 64;
/// Independent rounds (each a fresh nonce) per lane, so "exactly one 200"
/// is exercised across many races rather than one lucky interleaving. Fewer
/// rounds than the store-tier lanes: every submission here also costs a
/// signature verify + a delegated response signing, and the store tier —
/// where the atomicity actually lives — is already raced 50× elsewhere.
const ROUNDS: usize = 10;

/// Fire `TASKS` concurrent submissions of the SAME signed request at ONE
/// shared PEP and assert the end-to-end property: exactly one 200 and
/// `TASKS - 1` replay rejections (409).
async fn assert_exactly_one_served(proxy: Arc<HttpProfileProxy>, nonce: &str, now: i64) {
    let req = Arc::new(signed_request(nonce, now));
    let mut handles = Vec::new();
    for _ in 0..TASKS {
        let proxy = Arc::clone(&proxy);
        let req = Arc::clone(&req);
        handles.push(tokio::spawn(async move {
            proxy.handle(served(&req), now).await.status
        }));
    }
    let mut ok = 0usize;
    let mut replay = 0usize;
    for handle in handles {
        match handle.await.expect("task") {
            200 => ok += 1,
            409 => replay += 1,
            other => panic!("unexpected status {other} from the serving path"),
        }
    }
    assert_eq!(
        ok, 1,
        "nonce {nonce}: a {TASKS}-way race through one shared PEP must serve EXACTLY one"
    );
    assert_eq!(
        replay,
        TASKS - 1,
        "nonce {nonce}: every loser must be a 409 replay rejection"
    );
}

/// Race `ROUNDS` fresh nonces through ONE PEP over `store`.
async fn assert_every_round_serves_exactly_one(store: Arc<dyn AsyncAtomicReplayStore>) {
    let now = now();
    let proxy = Arc::new(proxy_over(store, 100, now));
    let prefix = unique_token();
    for round in 0..ROUNDS {
        assert_exactly_one_served(Arc::clone(&proxy), &format!("{prefix}-{round}"), now).await;
    }
}

/// In-memory reference tier — always on, no live infra.
#[test]
fn serving_path_admits_exactly_one_in_memory() {
    multi_thread_runtime().block_on(assert_every_round_serves_exactly_one(Arc::new(
        InMemoryAsyncAtomicReplayStore::new(),
    )));
}

/// LIVE Redis async tier through the full serving path: the cross-replica
/// coherence boundary is a real networked store (MCPRE-117 AC).
/// Skip-when-absent; hard-fail under `MCP_RE_REQUIRE_LIVE_INFRA`.
#[cfg(feature = "redis_replay")]
#[test]
fn serving_path_admits_exactly_one_over_live_redis() {
    let Some(url) = redis_url() else {
        return;
    };
    multi_thread_runtime().block_on(async {
        let store = super::live_infra::connect_redis(&url).await;
        assert_every_round_serves_exactly_one(store).await;
    });
}

/// TWO independent PEPs over ONE live Redis store: a nonce served by
/// replica A is replay-rejected by replica B — cross-replica coherence
/// stated through the full serving path, not at the store tier.
#[cfg(feature = "redis_replay")]
#[test]
fn two_replicas_share_one_live_redis_admission() {
    let Some(url) = redis_url() else {
        return;
    };
    multi_thread_runtime().block_on(async {
        let store = super::live_infra::connect_redis(&url).await;
        assert_replica_b_rejects_what_replica_a_admitted(store).await;
    });
}

/// LIVE etcd (CP/linearizable) async tier through the full serving path.
/// Skip-when-absent; hard-fail under `MCP_RE_REQUIRE_LIVE_INFRA`.
#[cfg(feature = "cpstore_etcd")]
#[test]
fn serving_path_admits_exactly_one_over_live_etcd() {
    let Some(endpoint) =
        super::live_infra::live_endpoint("MCP_RE_TEST_ETCD_URL", "full-serving-path etcd race")
    else {
        return;
    };
    multi_thread_runtime().block_on(async {
        let store = super::live_infra::connect_etcd(&endpoint);
        assert_every_round_serves_exactly_one(store).await;
    });
}

/// The live Redis endpoint for the full-serving-path race, or `None` to skip.
#[cfg(feature = "redis_replay")]
fn redis_url() -> Option<String> {
    super::live_infra::live_endpoint("MCP_RE_TEST_REDIS_URL", "full-serving-path Redis race")
}

/// Two distinct PEP instances (distinct delegated key material) sharing ONE
/// authoritative tier — the fleet shape. A nonce replica A admits, replica B
/// replay-rejects; a nonce no replica has seen is still admitted on B.
#[cfg(feature = "redis_replay")]
async fn assert_replica_b_rejects_what_replica_a_admitted(store: Arc<dyn AsyncAtomicReplayStore>) {
    let now = now();
    let a = proxy_over(Arc::clone(&store), 100, now);
    let b = proxy_over(store, 200, now);

    let prefix = unique_token();
    let req = signed_request(&format!("{prefix}-cross"), now);
    assert_eq!(
        a.handle(served(&req), now).await.status,
        200,
        "replica A serves it"
    );
    assert_eq!(
        b.handle(served(&req), now).await.status,
        409,
        "replica B replay-rejects a nonce replica A already admitted"
    );

    // Control: a nonce no replica has seen is admitted on B.
    let fresh = signed_request(&format!("{prefix}-fresh"), now);
    assert_eq!(
        b.handle(served(&fresh), now).await.status,
        200,
        "a distinct nonce is still admitted on replica B"
    );
}
