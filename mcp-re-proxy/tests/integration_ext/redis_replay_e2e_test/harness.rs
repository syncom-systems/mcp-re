// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
#![cfg(feature = "redis_replay")]
//! What the live Redis cases share: the environment gates that decide whether a case runs,
//! the real clock, the replay-key layout, and the node and pool constructors.

use std::sync::Arc;

use mcp_re_core::ReplayDecision;
use mcp_re_proxy::async_replay::{AsyncAtomicReplayStore, ReplayInsert};
use mcp_re_proxy::shared_replay::ReplayStoreError;
use mcp_re_proxy::RedisAsyncAtomicReplayStore;

/// Every entry in this file is charged to one signer; the per-actor budget is
/// exercised by its own test in `async_replay.rs`.
const TEST_ACTOR: &str = "did:example:test-signer";

const AUD: &str = "did:example:verifier";

/// The current Unix time from the REAL system clock.
pub(super) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as i64
}

/// A fresh retain-until a bounded window into the future from the REAL system clock.
/// The Redis store derives its `PX` TTL from its own wall clock and rejects a past
/// `retain_until` PRE-store (MCPS-08, fail closed), so a FIXED timestamp would make
/// these tests fail on any date past it.
pub(super) fn expires_soon() -> i64 {
    now_unix() + 3600
}

/// A per-run suffix for signer/nonce values, so each run of these tests targets a
/// key space of its own.
///
/// An admitted nonce stays in Redis for its whole `retain_until` window (600s–1h
/// here), and these tests assert a first insert is `Fresh`. A value fixed at compile
/// time therefore only holds against a pristine Redis: the next run inside the window
/// sees its own predecessor's key and gets `Replay`. Anchoring on the process clock
/// keeps every run independent, and the lane can be re-run against a long-lived Redis.
fn run_id() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos()
}

/// The signer a replay entry is charged under.
pub(super) struct Signer(String);

impl Signer {
    /// A signer owned by `test` for this run: the test's name plus a per-run suffix, so the
    /// test owns its key space and never collides with a prior run's still-live entry (see
    /// [`run_id`]).
    pub(super) fn for_test(test: &str) -> Self {
        Self(format!("did:example:host#{test}-{}", run_id()))
    }
}

/// A nonce no other call has used.
pub(super) struct Nonce(String);

impl Nonce {
    pub(super) fn fresh() -> Self {
        Self(mcp_re_test_paths::unique_test_nonce())
    }
}

/// A per-exchange replay key: length-prefixed `(signer, audience, nonce)` then
/// `sha256_hash_id` (lowercase hex). The PTTL test probes the SAME Redis key the store
/// inserts.
pub(super) fn composite_key(signer: &Signer, nonce: &Nonce) -> String {
    let (signer, nonce) = (&signer.0, &nonce.0);
    let preimage = format!(
        "{}:{}|{}:{}|{}:{}",
        signer.len(),
        signer,
        AUD.len(),
        AUD,
        nonce.len(),
        nonce,
    );
    mcp_re_core::sha256_hash_id(preimage.as_bytes())
}

/// The connection URL of a Redis the case runs against.
pub(super) struct RedisUrl(String);

impl RedisUrl {
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// CI opt-in: when `MCP_RE_REQUIRE_LIVE_INFRA` is set to any non-empty value, a
/// missing-infra SKIP must HARD-FAIL instead of passing, so CI cannot score an
/// unavailable backend as a green test. Unset (local dev) leaves skip behavior
/// unchanged.
fn require_live_infra() -> bool {
    std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty())
}

/// The URL in environment variable `var`, or `None` to skip. Hard-fails under
/// MCP_RE_REQUIRE_LIVE_INFRA, saying `why` the case must run there, so CI cannot score a
/// missing backend as a green skip.
fn live_url(var: &str, why: &str) -> Option<RedisUrl> {
    let url = std::env::var(var).ok().filter(|u| !u.trim().is_empty());
    if url.is_none() && require_live_infra() {
        panic!("MCP_RE_REQUIRE_LIVE_INFRA is set but {var} is unavailable — {why}");
    }
    url.map(RedisUrl)
}

/// The Redis URL the test should run against, or `None` to skip. A real shared backend is
/// not present in every environment.
pub(super) fn redis_url() -> Option<RedisUrl> {
    live_url(
        "MCP_RE_TEST_REDIS_URL",
        "this live e2e MUST run under CI, not skip",
    )
}

/// The replica's admin connection URL, or `None` to skip.
pub(super) fn replica_admin_url() -> Option<RedisUrl> {
    live_url(
        "MCP_RE_TEST_REDIS_REPLICA_URL",
        "the WAIT-quorum multi-replica proof MUST run under CI, not skip",
    )
}

/// The infrastructure a skipped case was missing.
pub(super) enum Missing {
    Redis,
    ReplicaTopology,
}

/// The notice a case prints when it skips for want of infrastructure.
pub(super) fn skip(test: &str, missing: Missing) {
    let what = match missing {
        Missing::Redis => "MCP_RE_TEST_REDIS_URL unset (no Redis available in this environment)",
        Missing::ReplicaTopology => {
            "MCP_RE_TEST_REDIS_URL / MCP_RE_TEST_REDIS_REPLICA_URL unset (no replica topology)"
        }
    };
    eprintln!("SKIP {test}: {what}");
}

/// A current-thread runtime the blocking test bodies drive the async store on.
pub(super) fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

pub(super) fn raw_conn(url: &RedisUrl) -> redis::Connection {
    redis::Client::open(url.as_str())
        .expect("open redis client")
        .get_connection()
        .expect("redis connection")
}

/// One proxy node: a store over its own Redis connection, driven on the case's runtime.
pub(super) struct Node<'rt> {
    rt: &'rt tokio::runtime::Runtime,
    store: RedisAsyncAtomicReplayStore,
}

impl<'rt> Node<'rt> {
    /// A store over a fresh Redis connection to `url`. Each call is an independent "node"
    /// (its own connection) sharing the one Redis.
    pub(super) fn connect(rt: &'rt tokio::runtime::Runtime, url: &RedisUrl) -> Self {
        let store = rt
            .block_on(RedisAsyncAtomicReplayStore::connect(url.as_str()))
            .expect("connect to MCP_RE_TEST_REDIS_URL Redis");
        Self { rt, store }
    }

    /// A `WAIT 1`-quorum store over a fresh primary connection: a fresh insert must be
    /// acknowledged by at least one replica within `wait_timeout_ms` or it fails closed.
    pub(super) fn connect_with_wait_quorum(
        rt: &'rt tokio::runtime::Runtime,
        primary_url: &RedisUrl,
        wait_timeout_ms: u64,
    ) -> Self {
        let store = rt
            .block_on(RedisAsyncAtomicReplayStore::connect_with_wait_quorum(
                primary_url.as_str(),
                mcp_re_proxy::async_redis_store::system_clock(),
                Some((1, wait_timeout_ms)),
            ))
            .expect("connect the store to the primary Redis");
        Self { rt, store }
    }

    /// Insert `(signer, AUD, nonce)` retained until `retain_until`.
    pub(super) fn insert(
        &self,
        signer: &Signer,
        nonce: &Nonce,
        retain_until: i64,
    ) -> Result<ReplayDecision, ReplayStoreError> {
        let key = composite_key(signer, nonce);
        self.rt
            .block_on(self.store.atomic_insert_if_absent(ReplayInsert::new(
                &key,
                TEST_ACTOR,
                retain_until,
                0,
            )))
    }
}

/// A pooled store of `size` connections to `url`, with an optional `(replicas, timeout_ms)`
/// WAIT quorum.
pub(super) fn connect_pool(
    rt: &tokio::runtime::Runtime,
    url: &RedisUrl,
    wait_quorum: Option<(u32, u64)>,
    size: usize,
) -> Arc<RedisAsyncAtomicReplayStore> {
    Arc::new(
        rt.block_on(RedisAsyncAtomicReplayStore::connect_pooled(
            url.as_str(),
            mcp_re_proxy::async_redis_store::system_clock(),
            wait_quorum,
            size,
        ))
        .unwrap_or_else(|e| panic!("connect a {size}-connection pool to Redis: {e:?}")),
    )
}

/// Insert every key of `keys` concurrently through `store`, one task each, and return the
/// decisions in completion order.
pub(super) fn insert_concurrently(
    rt: &tokio::runtime::Runtime,
    store: &Arc<RedisAsyncAtomicReplayStore>,
    keys: Vec<String>,
    retain_until: i64,
) -> Vec<Result<ReplayDecision, ReplayStoreError>> {
    rt.block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for key in keys {
            let store = Arc::clone(store);
            set.spawn(async move {
                let insert = ReplayInsert::new(&key, TEST_ACTOR, retain_until, 0);
                store.atomic_insert_if_absent(insert).await
            });
        }
        set.join_all().await
    })
}

/// How many of `decisions` are `wanted`.
pub(super) fn count(
    decisions: &[Result<ReplayDecision, ReplayStoreError>],
    wanted: &ReplayDecision,
) -> usize {
    decisions
        .iter()
        .filter(|r| r.as_ref().ok() == Some(wanted))
        .count()
}
