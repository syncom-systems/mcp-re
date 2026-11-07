//! MCPS-84 (ADR-MCPS-049 W2) — trust-epoch invalidation source.
//!
//! A networked [`InvalidationChannel`](crate::trust_plane::InvalidationChannel)
//! (ADR-MCPS-021 Tier 3) driven by a **monotonic trust-epoch counter**: an
//! operator advances a shared epoch (`mcp-re-proxy trust-epoch advance`) whenever the trust
//! store changes (a key revoked or rotated). Each replica polls the epoch state — the
//! counter and the generation the last advance wrote beside it; when either differs
//! from what this node last saw, the source emits a single
//! coarse [`InvalidationEvent::FlushAll`] so the bounded trust cache drops all
//! positive entries and re-resolves live.
//!
//! Why an epoch, not pub/sub: pub/sub is fire-and-forget — a replica that
//! reconnects or restarts silently misses a one-shot message and never recovers.
//! An epoch is pull-based and **self-healing**: on any poll a node compares the
//! current epoch to the last it saw, so it detects a change that happened during
//! an outage without having observed the intermediate event. The poll interval is
//! the bounded window `T`; a read failure fails closed (the source goes unhealthy
//! and the cache reverts to its bounded-`T` guarantee — never zero-window).
//!
//! The epoch→event logic is generic over an [`EpochReader`] so it is unit-tested
//! without Redis; [`RedisEpochReader`] (feature `redis_replay`) is the networked
//! reader, proven by the gated live e2e.

pub mod advance;
mod poller;
pub(crate) mod raise;
#[cfg(feature = "redis_replay")]
mod redis_reader;
mod shared;
mod source;
mod state;

pub use poller::trust_epoch_poller_body;
#[cfg(feature = "redis_replay")]
pub use redis_reader::redis_trust_epoch_source;
#[cfg(feature = "redis_replay")]
pub use redis_reader::RedisEpochReader;
pub use shared::SharedEpochChannel;
pub use source::TrustEpochSource;
pub use state::EpochState;

/// Default Redis key holding the monotonic trust epoch.
pub const DEFAULT_TRUST_EPOCH_KEY: &str = "mcp-re:trust:epoch";

/// A failure to read the current trust epoch (connection or op error). Surfaced as
/// a source-unhealthy signal → bounded-`T` fallback, never a silent success.
#[derive(Debug)]
pub struct EpochReadError(pub String);

/// The seam between the epoch→invalidation logic and its backend, so the logic is
/// testable without a live store. An absent counter is a read failure, never `0`.
pub trait EpochReader: Send + Sync {
    /// The counter and its generation in one read, so an advance cannot fall between them.
    /// An ABSENT key and an operational failure are both [`EpochReadError`] (fail closed) —
    /// see [`RedisEpochReader::require_present`] for why absence is not a baseline.
    fn read_state(&self) -> Result<EpochState, EpochReadError>;

    /// The counter of [`read_state`](Self::read_state).
    fn read_epoch(&self) -> Result<i64, EpochReadError> {
        self.read_state().map(|state| state.counter)
    }
}
