// SPDX-License-Identifier: Apache-2.0
//! Establishing one concrete backend, and refusing the ones this build does not carry.
//!
//! Every refusal here is a statement about the BUILD — a backend that was not compiled in —
//! or about the ENVIRONMENT — a store that would not answer. Refusals knowable from
//! configuration alone were already decided by layer A.
//!
//! The two backends differ in more than their protocol. The etcd store drives its own
//! requests, so it needs no share of the control runtime and never asks for one; the Redis
//! one does, and its `WAIT` window has to be sized BEFORE connecting or the
//! declared durability would be advertised and not enforced.

use crate::async_replay::AsyncReplayTier;
use crate::control_runtime::ControlRuntimeProvision;
use crate::deployment_request::ReplayRedisPoolSize;
use crate::replay_tier::ReplayDurabilityTier;

/// The retention padding this deployment's shared store applies, stated at startup.
///
/// An operator told the replay window is `--max-clock-skew` is told something shorter than
/// what the store keeps, so the extra retention is announced beside the tier.
#[cfg(any(feature = "redis_replay", feature = "cpstore_etcd"))]
fn divergence_audit_line(freshness: crate::config_state::FreshnessWindow) -> String {
    format!(
        "replay retention padded by {}s for replica clock divergence \
         (--replay-clock-divergence-secs)",
        freshness.replica_clock_divergence().secs()
    )
}

/// The CP/linearizable backend: an async etcd CAS per admitted nonce.
///
/// The store drives its own requests, so it needs no share of the control runtime and
/// never asks the provision for one.
#[cfg_attr(not(feature = "cpstore_etcd"), allow(unused_variables))]
pub(super) fn establish_etcd(
    endpoint: &str,
    tier: &ReplayDurabilityTier,
    freshness: crate::config_state::FreshnessWindow,
) -> Result<AsyncReplayTier, String> {
    #[cfg(feature = "cpstore_etcd")]
    {
        let store = std::sync::Arc::new(
            crate::async_etcd_store::EtcdAsyncAtomicReplayStore::connect_with(
                endpoint,
                freshness
                    .replica_clock_divergence()
                    .retention_clock(crate::async_etcd_store::system_clock()),
            )
            .map_err(|e| e.to_string())?,
        );
        eprintln!("mcp-re-proxy: replay tier = shared (CP/linearizable; async etcd backend)");
        eprintln!("mcp-re-proxy: {}", tier.startup_audit_line("etcd"));
        eprintln!("mcp-re-proxy: {}", divergence_audit_line(freshness));
        Ok(AsyncReplayTier::new(store, freshness))
    }
    #[cfg(not(feature = "cpstore_etcd"))]
    Err(
        "--replay-durability-tier linearizable requires a build with the `cpstore_etcd` feature"
            .to_string(),
    )
}

/// The horizontally-scaled backend: async Redis `SET NX PX`, connected in the tier the
/// plan declares.
///
/// The declared WAIT quorum is a construction parameter of the store that serves:
/// `startup_audit_line` has already promised "WAIT timeout or insufficient acks fail
/// closed", so a store built without it would run plain `SET NX PX` and the promise would
/// be audited but unenforced. The same value sizes the client-side response timeout, so a
/// declared `redis-wait-quorum:2:2000` can actually wait 2000ms.
///
/// `pool` is how many connections the store holds open. Each one runs the same tier, so
/// it bounds how many admissions can be waiting on `WAIT` at once and nothing else.
#[cfg_attr(not(feature = "redis_replay"), allow(unused_variables))]
pub(super) fn establish_redis(
    url: &str,
    pool: ReplayRedisPoolSize,
    tier: &ReplayDurabilityTier,
    freshness: crate::config_state::FreshnessWindow,
    control: &ControlRuntimeProvision,
) -> Result<AsyncReplayTier, String> {
    #[cfg(feature = "redis_replay")]
    {
        let connection = redis_connection(tier, pool, freshness, control)?;
        let store = connection
            .runtime
            .block_on(crate::RedisAsyncAtomicReplayStore::connect_pooled(
                url,
                connection.clock,
                connection.wait_quorum,
                connection.pool.get(),
            ))
            .map_err(|e| format!("connect redis async replay store: {e:?}"))?;
        eprintln!("mcp-re-proxy: replay tier = shared (horizontally-scaled; async Redis backend)");
        eprintln!("mcp-re-proxy: {}", tier.startup_audit_line("redis"));
        eprintln!("mcp-re-proxy: {}", pool_audit_line(connection.pool));
        eprintln!("mcp-re-proxy: {}", divergence_audit_line(freshness));
        Ok(AsyncReplayTier::new(std::sync::Arc::new(store), freshness))
    }
    #[cfg(not(feature = "redis_replay"))]
    Err(
        "--replay-cache shared (redis) requires a build with the `redis_replay` feature"
            .to_string(),
    )
}

/// The effective Redis replay pool, stated at startup beside the tier it serves.
#[cfg(feature = "redis_replay")]
fn pool_audit_line(pool: ReplayRedisPoolSize) -> String {
    format!(
        "replay redis pool = {} connections (--replay-redis-pool-size; default {})",
        pool.get(),
        ReplayRedisPoolSize::DEFAULT.get()
    )
}

/// What connecting the Redis store needs, read off the plan before anything is contacted:
/// the control runtime's handle, the clock held back by the declared divergence, the
/// declared `WAIT` quorum, and the pool size. Separate from the connect so each is
/// assertable in the `redis_replay` lane without a live server.
#[cfg(feature = "redis_replay")]
struct RedisConnection {
    runtime: tokio::runtime::Handle,
    clock: crate::async_redis_store::UnixClock,
    wait_quorum: Option<(u32, u64)>,
    pool: ReplayRedisPoolSize,
}

/// The handle is asked for HERE, by the arm whose plan selected Redis, so the store that
/// needs the control runtime is the request that starts it. The only refusal is the
/// runtime failing to build.
#[cfg(feature = "redis_replay")]
fn redis_connection(
    tier: &ReplayDurabilityTier,
    pool: ReplayRedisPoolSize,
    freshness: crate::config_state::FreshnessWindow,
    control: &ControlRuntimeProvision,
) -> Result<RedisConnection, String> {
    let runtime = control.handle()?;
    Ok(RedisConnection {
        runtime,
        clock: freshness
            .replica_clock_divergence()
            .retention_clock(crate::async_redis_store::system_clock()),
        wait_quorum: tier.wait_quorum_params(),
        pool,
    })
}

#[cfg(test)]
mod tests {
    /// Each shared backend is connected on the clock held back by the declared replica
    /// clock divergence. The padding lives in that clock, so a backend connected on the bare
    /// system clock is a store whose records lapse early on a fast replica, and nothing in
    /// the store can tell.
    #[test]
    fn both_shared_backends_are_connected_on_the_held_back_clock() {
        let source = include_str!("backends.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("a production half");
        for backend in ["fn establish_etcd", "fn establish_redis"] {
            let from = production
                .find(backend)
                .expect("the backend is established here");
            let body = &production[from + backend.len()..];
            let body = body.split("pub(super) fn ").next().expect("a body");
            assert_eq!(
                body.matches(".retention_clock(").count(),
                1,
                "{backend} must derive its store's clock from the declared divergence exactly once"
            );
        }
    }
    /// The Redis arm reads its `WAIT` quorum off the plan before contacting anything, so
    /// the store that serves is built in the tier the startup audit line advertises. The
    /// fixture declares `redis-wait-quorum:1:100`; a connection built with no quorum would
    /// run plain `SET NX PX` under a fail-closed claim.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn the_redis_arm_connects_in_the_declared_wait_quorum() {
        let plan = crate::config_state::test_support::redis_replay_plan();
        let control = crate::control_runtime::ControlRuntimeProvision::idle();
        let connection = super::redis_connection(
            plan.tier(),
            crate::deployment_request::ReplayRedisPoolSize::DEFAULT,
            crate::config_state::test_support::freshness(60),
            &control,
        )
        .unwrap_or_else(|e| panic!("a planned redis tier connects on the control runtime: {e}"));
        assert_eq!(connection.wait_quorum, Some((1, 100)));
    }

    /// The pool the plan carries is the pool the store is connected with, and the startup
    /// line states that effective size.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn the_redis_arm_connects_with_the_planned_pool_and_reports_it() {
        let plan = crate::config_state::test_support::redis_replay_plan();
        let control = crate::control_runtime::ControlRuntimeProvision::idle();
        let pool = crate::deployment_request::ReplayRedisPoolSize::new(32).expect("in range");
        let connection = super::redis_connection(
            plan.tier(),
            pool,
            crate::config_state::test_support::freshness(60),
            &control,
        )
        .unwrap_or_else(|e| panic!("a planned redis tier connects on the control runtime: {e}"));
        assert_eq!(connection.pool, pool);
        assert_eq!(connection.wait_quorum, Some((1, 100)));
        let line = super::pool_audit_line(connection.pool);
        assert!(
            line.contains("replay redis pool = 32 connections"),
            "{line}"
        );
    }

    /// The Redis arm runs on the shared control runtime, and asking for it is what starts
    /// it: the store that needs the runtime and the runtime it gets cannot disagree.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn the_redis_arm_runs_on_the_control_runtime_it_asked_for() {
        let plan = crate::config_state::test_support::redis_replay_plan();
        let mut control = crate::control_runtime::ControlRuntimeProvision::idle();
        let connection = super::redis_connection(
            plan.tier(),
            crate::deployment_request::ReplayRedisPoolSize::DEFAULT,
            crate::config_state::test_support::freshness(60),
            &control,
        )
        .unwrap_or_else(|e| panic!("a planned redis tier connects on the control runtime: {e}"));
        let started = control
            .take()
            .expect("the redis arm's request started the control runtime");
        assert_eq!(connection.runtime.id(), started.handle().id());
    }
}
