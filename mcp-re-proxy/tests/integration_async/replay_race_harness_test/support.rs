//! Constants and helpers shared by every lane of the replay race harness.

/// A retain-until far in the future so the store's defensive pre-store staleness
/// guard (`is_stale_pre_store`, MCPS-08) never rejects the submission before the
/// race — the store judges it against its own clock, so any value past that
/// clock is admissible and the ONLY thing that decides Fresh/Replay is the atomic
/// insert.
pub(super) const FAR_FUTURE_RETAIN_UNTIL: i64 = 4_000_000_000;

/// How many concurrent submitters pile onto the one replay key per race round.
pub(super) const RACE_WIDTH: usize = 64;

/// How many independent race rounds (each a fresh key) every tier test runs, so
/// the "exactly one Fresh" property is exercised across many distinct races rather
/// than a single lucky interleaving.
pub(super) const RACE_ROUNDS: usize = 50;

/// A token distinct per call and per run on a shared persistent store: the
/// test-nonce (process id, process address, counter) and the wall-clock
/// nanoseconds. A LIVE race lane's keys must never collide with another lane's or
/// a prior run's, because the stores outlive the test process and keep every key
/// under a far-future TTL — a collision would show up as ZERO `Fresh`, not as a
/// false pass. The caller reads the token ONCE and reuses it for every round, so
/// all submitters in a round still submit the IDENTICAL key.
pub(super) fn unique_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the system clock is after the Unix epoch")
        .as_nanos();
    format!("{}-{nanos}", mcp_re_test_paths::unique_test_nonce())
}

/// The multi-thread runtime the async race lanes await on.
pub(super) fn multi_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("runtime")
}
