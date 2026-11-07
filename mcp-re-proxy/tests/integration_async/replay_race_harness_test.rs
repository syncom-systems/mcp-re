//! MCPRE-109 (ADR-MCPRE-051 §4) — replay race harness: the authoritative
//! replay tier admits EXACTLY ONE `Fresh` under true concurrency.
//!
//! ADR-MCPRE-051 §4 makes replay a globally coherent admission decision: a
//! request is dispatchable *only* if its replay key is **atomically inserted**
//! into the authoritative replay tier ([`AtomicReplayStore`]). The load-bearing
//! property, on every release, is:
//!
//! > N concurrent submissions of the SAME signed request (same replay key),
//! > across cores and across replicas, yield EXACTLY ONE `Fresh` and N−1
//! > `Replay` — and if the store is unavailable, ZERO `Fresh` (fail closed).
//!
//! This harness proves that property deterministically. Determinism comes from a
//! [`Barrier`] that releases all racing threads at once (maximising real
//! contention) followed by an EXACT count assertion — the atomic
//! insert-if-absent contract makes "exactly one `Fresh`" hold regardless of
//! thread interleaving, so there is no timing/sleep assertion to be flaky.
//!
//! Layering (ADR-MCPRE-051 §4): `Fresh` is only ever the result of a successful
//! L2 atomic insert, so the race is proven at the [`AtomicReplayStore`] tier —
//! the sole authority. The [`SharedReplayCache`] wrapper adds only pure,
//! deterministic skew-folding + composite-key construction over that tier; its
//! correctness and cross-replica coherence are covered single-threaded in
//! `shared_cache`. The full-stack variant — N concurrent submissions of the
//! SAME signed RFC 9421 request through ONE shared serving `HttpProfileProxy`
//! (MCPRE-117 AC) — lives in the `http_profile_full_stack` module,
//! over the in-memory reference tier and over each live store.
//!
//! Backends: the default build races the in-tree reference
//! [`InMemoryAtomicReplayStore`] (an `Arc<Mutex<…>>`, a real store — not a mock),
//! so this runs on every `bazel test //...` with no live infra. The Redis and
//! etcd backends race the SAME harness on the live store when their feature is
//! compiled and their endpoint env var is set (skip-when-absent, hard-fail under
//! `MCP_RE_REQUIRE_LIVE_INFRA`), mirroring `redis_replay_e2e_test.rs`.

mod http_profile_full_stack;
#[cfg(all(
    feature = "async_serve",
    any(feature = "redis_replay", feature = "cpstore_etcd")
))]
mod live_infra;
#[cfg(all(
    feature = "async_serve",
    any(feature = "redis_replay", feature = "cpstore_etcd")
))]
mod live_tier;
mod shared_cache;
mod support;
mod tier;
