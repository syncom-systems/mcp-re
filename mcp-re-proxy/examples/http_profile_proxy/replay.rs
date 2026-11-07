//! The replay admission the proof front runs, chosen from the environment.

use std::sync::Arc;

use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::config_state::FreshnessWindow;
use mcp_re_proxy::http_profile_dispatch::ReplayAdmission;
use mcp_re_proxy::http_profile_dispatch::ReplayPosture;
use mcp_re_proxy::replay_tier::ReplayDurabilityTier;
#[cfg(feature = "redis_replay")]
use mcp_re_proxy::RedisAsyncAtomicReplayStore;

/// The replay admission and whether it runs under fleet-strict.
///
/// A shared Redis tier under fleet-strict when `HPP_REDIS_URL` is set (the multi-replica
/// production posture — a nonce admitted on one replica is rejected on any other sharing the
/// store); otherwise a single-process in-memory cache (fleet_strict off).
pub(super) async fn from_env() -> (ReplayAdmission, bool) {
    match std::env::var("HPP_REDIS_URL") {
        Ok(url) => (redis_admission(url).await, true),
        Err(_) => (in_memory_admission(), false),
    }
}

fn in_memory_admission() -> ReplayAdmission {
    ReplayAdmission::new(
        AsyncReplayTier::new(
            Arc::new(InMemoryAsyncAtomicReplayStore::new()),
            FreshnessWindow::new(0).expect("0s is inside the §5.1 skew bound"),
        ),
        ReplayPosture::SingleProcess,
    )
}

fn declared_tier() -> ReplayDurabilityTier {
    let tier =
        std::env::var("HPP_REPLAY_TIER").unwrap_or_else(|_| "redis-wait-quorum:2:2000".to_string());
    ReplayDurabilityTier::parse(&tier).expect("HPP_REPLAY_TIER")
}

#[cfg(feature = "redis_replay")]
async fn redis_admission(url: String) -> ReplayAdmission {
    let tier = declared_tier();
    // As the shipped `replay_plane::backends::establish_redis`: the declared
    // tier is a construction parameter of the store that serves.
    let store = RedisAsyncAtomicReplayStore::connect_with_wait_quorum(
        &url,
        mcp_re_proxy::async_redis_store::system_clock(),
        tier.wait_quorum_params(),
    )
    .await
    .unwrap_or_else(|e| panic!("connect redis {url}: {e:?}"));
    eprintln!("{}", tier.startup_audit_line("redis"));
    ReplayAdmission::new(
        AsyncReplayTier::new(
            Arc::new(store),
            FreshnessWindow::new(5).expect("5s is inside the §5.1 skew bound"),
        ),
        ReplayPosture::FleetStrict(tier),
    )
}

#[cfg(not(feature = "redis_replay"))]
async fn redis_admission(url: String) -> ReplayAdmission {
    let _ = (url, declared_tier());
    panic!(
        "HPP_REDIS_URL is set but this example was built without the \
         `redis_replay` feature; rebuild with \
         `--features redis_replay` for the shared multi-replica tier"
    );
}
