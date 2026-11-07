//! Live-infra lanes — Redis / etcd race the SAME harness (skip-when-absent).

use std::sync::Arc;

/// CI opt-in: when `MCP_RE_REQUIRE_LIVE_INFRA` is set to any non-empty value, a
/// missing backend endpoint HARD-FAILS instead of skipping, so the live lane
/// cannot be silently scored green.
fn require_live_infra() -> bool {
    std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty())
}

/// Read a live-store endpoint from `var`, or decide how to skip: silently when
/// live infra is optional, by panic when it is required (so an absent store can
/// never be scored as a pass). `lane` names the race being skipped.
pub(super) fn live_endpoint(var: &str, lane: &str) -> Option<String> {
    let endpoint = std::env::var(var).ok().filter(|u| !u.trim().is_empty());
    if endpoint.is_none() {
        assert!(
            !require_live_infra(),
            "MCP_RE_REQUIRE_LIVE_INFRA is set but {var} is unavailable; \
             the {lane} cannot be scored as passing without a live store"
        );
        eprintln!("skipping the {lane}: {var} unset");
    }
    endpoint
}

/// The async Redis authoritative tier (`SET NX PX` over the tokio async client).
#[cfg(feature = "redis_replay")]
pub(super) async fn connect_redis(url: &str) -> Arc<mcp_re_proxy::RedisAsyncAtomicReplayStore> {
    Arc::new(
        mcp_re_proxy::RedisAsyncAtomicReplayStore::connect(url)
            .await
            .expect("connect the async Redis replay store"),
    )
}

/// The async etcd authoritative tier. `connect` is infallible (it only records the
/// endpoint); a wrong or unreachable gateway surfaces as a per-request
/// `Unavailable`, i.e. ZERO Fresh — never a false Fresh — which an exact count
/// catches.
#[cfg(feature = "cpstore_etcd")]
pub(super) fn connect_etcd(
    endpoint: &str,
) -> Arc<mcp_re_proxy::async_etcd_store::EtcdAsyncAtomicReplayStore> {
    Arc::new(
        mcp_re_proxy::async_etcd_store::EtcdAsyncAtomicReplayStore::connect(endpoint)
            .expect("etcd endpoint"),
    )
}
