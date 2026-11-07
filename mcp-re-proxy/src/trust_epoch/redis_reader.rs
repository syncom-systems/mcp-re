//! The Redis-backed [`EpochReader`](super::EpochReader) (feature `redis_replay`).

use std::sync::Mutex;

use super::EpochReadError;
use super::EpochReader;
use super::EpochState;
use super::TrustEpochSource;

/// Worst-case wall time ONE [`EpochReader::read_epoch`] may consume.
///
/// The delegated rotation loop reads the epoch on its critical path at `exp - overlap`
/// and cannot mint a successor until the read returns, so this budget is spent out of
/// the rotation overlap. A read allowed to outlast the overlap lets a single
/// half-open (not down) connection consume the whole minting window: the successor is
/// never issued, the current key reaches its `exp`, and every replica answers
/// `mcp-re.delegated_signing_unavailable` on 100% of requests while the root issuer is
/// healthy and the epoch never changed. The default overlap is 60s, so the budget
/// leaves the great majority of it for the mint itself.
pub(super) const TRUST_EPOCH_READ_BUDGET: std::time::Duration = std::time::Duration::from_secs(8);

/// Bounded network operations in one read: connect, `GET`, and — on a transient error
/// — a reconnect and the retried `GET`.
pub(super) const TRUST_EPOCH_OPS_PER_READ: u32 = 4;

/// Bounded connect/op timeout so a sinkholed/half-open Redis cannot wedge the
/// serve loop: the trust lookup runs before dispatch, so an unbounded blocking GET
/// would stall the whole proxy. Sized so the WHOLE read fits in
/// [`TRUST_EPOCH_READ_BUDGET`], since it is the read the caller waits on, not one
/// socket operation.
pub(super) const TRUST_EPOCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(
    TRUST_EPOCH_READ_BUDGET.as_secs() / TRUST_EPOCH_OPS_PER_READ as u64,
);

/// A [`EpochReader`] that reads the trust epoch and its generation from Redis in one `MGET`,
/// with a bounded connection and ONE reconnect-and-retry on a broken connection.
pub struct RedisEpochReader {
    pub(super) client: redis::Client,
    /// `None` until the first successful connection. Deferring it lets a replica start
    /// (and keep retrying) while the epoch store is briefly unreachable, instead of the
    /// one-shot startup connect that used to leave a replica with no cross-replica
    /// kill switch for its entire lifetime.
    pub(super) conn: Mutex<Option<redis::Connection>>,
    pub(super) epoch_key: String,
}

impl RedisEpochReader {
    /// An ABSENT epoch key is a read FAILURE, not epoch 0.
    ///
    /// A nil is indistinguishable from a live counter at 0, and treating it as
    /// epoch 0 would hide two failures:
    ///
    ///   * a `--trust-epoch-key` naming a key nobody advances, in the wrong database, or
    ///     since deleted would leave the Tier-3 kill switch inert while the startup
    ///     line advertised a pushed revocation window;
    ///   * a counter lost to a snapshot restore, FLUSHDB, LRU eviction or a failover
    ///     would let a restarting replica re-mint under `<base>#0`, silently undoing
    ///     a revocation inside the `{current, previous}` acceptance window.
    ///
    /// Failing closed makes both of those an unhealthy source, which reverts the
    /// surfaced guarantee to bounded-`T` and refuses to mint under a rolled-back
    /// epoch. Seeding the key (`SET <key> 0`) is a one-line deployment step; silently
    /// treating its absence as a live baseline is not recoverable after the fact.
    pub(super) fn require_present(
        value: Option<i64>,
        epoch_key: &str,
    ) -> Result<i64, EpochReadError> {
        value.ok_or_else(|| {
            EpochReadError(format!(
                "trust-epoch key {epoch_key:?} does not exist. An absent key is NOT epoch 0: it \
                 is indistinguishable from a counter that was never created, was deleted, or \
                 was lost to a restore/eviction, and reading it as a baseline would leave the \
                 push kill switch inert or let a restarted replica mint under a rolled-back \
                 epoch. Seed it with SET {epoch_key} 0 before serving."
            ))
        })
    }

    /// Connect to `url` and read epoch key `epoch_key` (e.g.
    /// [`DEFAULT_TRUST_EPOCH_KEY`](super::DEFAULT_TRUST_EPOCH_KEY)). Fails closed on an unreachable backend.
    pub fn connect(url: &str, epoch_key: impl Into<String>) -> Result<Self, EpochReadError> {
        let reader = Self::connect_lazy(url, epoch_key)?;
        // Eager callers want the connection proven now.
        reader.read_state()?;
        Ok(reader)
    }

    /// Build a reader WITHOUT contacting the store. `redis::Client::open` only parses
    /// the URL, so this cannot fail on an unreachable backend; the connection is
    /// established on the first [`read_epoch`](EpochReader::read_epoch) and re-established
    /// after any failure. A read while the store is down still returns
    /// [`EpochReadError`] — lazy connectivity changes WHEN we try, never whether an
    /// unreadable epoch is treated as fail-closed.
    pub fn connect_lazy(url: &str, epoch_key: impl Into<String>) -> Result<Self, EpochReadError> {
        use crate::deployment_request::RedactedLocator;
        let client = redis::Client::open(url)
            .map_err(|e| EpochReadError(format!("open redis {}: {e}", RedactedLocator::of(url))))?;
        Ok(RedisEpochReader {
            client,
            conn: Mutex::new(None),
            epoch_key: epoch_key.into(),
        })
    }

    pub(super) fn fresh_conn(client: &redis::Client) -> Result<redis::Connection, EpochReadError> {
        let c = client
            .get_connection_with_timeout(TRUST_EPOCH_TIMEOUT)
            .map_err(|e| EpochReadError(format!("connect: {e}")))?;
        // Best-effort socket timeouts; a failure to set them is not fatal (the
        // connect timeout already bounded the handshake).
        let _ = c.set_read_timeout(Some(TRUST_EPOCH_TIMEOUT));
        let _ = c.set_write_timeout(Some(TRUST_EPOCH_TIMEOUT));
        Ok(c)
    }
}

/// A Redis error meaning the connection is broken and must be replaced (one
/// reconnect-and-retry).
pub(super) fn is_transient(error: &redis::RedisError) -> bool {
    error.is_io_error()
        || error.is_connection_dropped()
        || error.is_connection_refusal()
        || error.is_unrecoverable_error()
}

impl EpochReader for RedisEpochReader {
    fn read_state(&self) -> Result<EpochState, EpochReadError> {
        self.mget_state()
    }
}

/// Build a networked trust-epoch invalidation source over Redis for the ADR-021
/// Push tier. Returns an error string suitable for a fail-closed startup abort.
pub fn redis_trust_epoch_source(
    url: &str,
    epoch_key: &str,
) -> Result<TrustEpochSource<RedisEpochReader>, String> {
    let reader = RedisEpochReader::connect(url, epoch_key).map_err(|e| e.0)?;
    Ok(TrustEpochSource::new(reader))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY;

    /// The delegated rotation loop blocks on ONE `read_epoch` at `exp - overlap` and
    /// cannot mint until it returns, so the read's worst case is spent out of the
    /// overlap. Sized above it, a single half-open connection consumes the whole
    /// minting window and takes response signing down fleet-wide at the current key's
    /// `exp` — an outage produced by timeout sizing, not by a lost kill switch.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn one_epoch_read_cannot_consume_the_rotation_overlap() {
        /// `--delegated-overlap-secs` default (cli.rs).
        const DEFAULT_OVERLAP: std::time::Duration = std::time::Duration::from_secs(60);
        assert!(
            TRUST_EPOCH_TIMEOUT * TRUST_EPOCH_OPS_PER_READ <= TRUST_EPOCH_READ_BUDGET,
            "every network operation a single read can issue must fit the budget"
        );
        assert!(
            TRUST_EPOCH_READ_BUDGET * 2 <= DEFAULT_OVERLAP,
            "the read must leave the overlap mostly free for the mint it precedes"
        );
    }

    /// An ABSENT epoch key is a read failure, never a live epoch 0.
    ///
    /// The e2e shows this against a real Redis by deleting the key; this is the rule at
    /// the seam that decides it, so the property is measured in the default battery under
    /// the Redis feature rather than only where a live store is provisioned.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn an_absent_epoch_key_is_a_read_failure_not_epoch_zero() {
        let Err(err) = RedisEpochReader::require_present(None, "mcp-re:trust:epoch") else {
            panic!("an absent key must fail closed, not read as epoch 0");
        };
        assert!(
            err.0.contains("does not exist"),
            "the refusal names the absent key so the operator can seed it: {}",
            err.0
        );
        assert_eq!(
            RedisEpochReader::require_present(Some(0), "k").ok(),
            Some(0),
            "a present counter at 0 is a live baseline: presence is the fact, not the value"
        );
    }

    /// LOAD-BEARING (Owner Ruling 6): the configured `--trust-epoch-redis-url` reaches this
    /// message on EVERY open failure, and a WELL-FORMED URL is exactly the shape that
    /// carries a password. Neither the credential nor the complete configured string may
    /// appear in what an operator reads, and the projection must not change which URLs open.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn an_open_failure_names_the_store_without_the_credential_or_the_configured_url() {
        const CONFIGURED: &str = "https://ops:hunter2@epoch.internal:6379/0";
        let Err(err) = RedisEpochReader::connect_lazy(CONFIGURED, DEFAULT_TRUST_EPOCH_KEY) else {
            panic!("a non-redis scheme is not a redis URL and must not open");
        };
        assert!(
            !err.0.contains("hunter2"),
            "the configured password reached the diagnostic: {}",
            err.0
        );
        assert!(
            !err.0.contains(CONFIGURED),
            "the complete configured URL was echoed: {}",
            err.0
        );
        assert!(
            err.0.contains("epoch.internal:6379"),
            "an operator still learns which store failed to open: {}",
            err.0
        );
        assert!(
            RedisEpochReader::connect_lazy("redis://epoch:6379", DEFAULT_TRUST_EPOCH_KEY).is_ok(),
            "redacting the diagnostic must not change which URLs open"
        );
    }

    /// No source is built over a store that does not answer. The trust plane spawns its
    /// poller only over a source this returned, so the eager first read is what refuses a
    /// push tier configured against an unreachable store at startup, instead of starting it
    /// on the bounded-`T` fallback with a poller that has never read a baseline.
    ///
    /// The signing plane opens its own reader of the same store and refuses on its own read,
    /// in `signing_plane::rotation_owner_tests`.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn an_unreachable_epoch_store_builds_no_source() {
        // An ephemeral port, bound to learn it and released again: the URL parses, and the
        // first read then fails to connect, without a hardcoded port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port");
        let port = listener.local_addr().expect("the bound address").port();
        drop(listener);
        let Err(err) = redis_trust_epoch_source(
            &format!("redis://127.0.0.1:{port}"),
            DEFAULT_TRUST_EPOCH_KEY,
        ) else {
            panic!("a store that does not answer must not yield a source");
        };
        assert!(
            err.starts_with("connect:"),
            "the refusal must be the failed connection, not a parse error: {err}"
        );
    }
}
