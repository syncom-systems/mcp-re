//! MCPRE (ADR-MCPRE-051 §4) — the ASYNC etcd authoritative replay backend.
//!
//! A CP/linearizable put-if-absent under a bounded lease, issued over an ASYNC `hyper`
//! client to etcd's v3 JSON gateway so the insert is AWAITED on the per-core request
//! path and never blocks a runtime worker (ADR-MCPRE-051 §4 — "the per-core Redis/etcd
//! clients are async and pipelined"). It implements
//! [`AsyncAtomicReplayStore`](crate::async_replay::AsyncAtomicReplayStore), so an
//! [`AsyncReplayTier`](crate::async_replay::AsyncReplayTier) over it gives the
//! serving path a genuinely durable, LINEARIZABLE cross-process authoritative tier.
//!
//! Protocol (the wire shape and its pure helpers live in [`protocol`]):
//!   * `POST /v3/lease/grant` mints a lease with a BOUNDED TTL (so a recorded nonce
//!     self-expires at the freshness window even if the proxy dies), granted only when
//!     no live lease already expires at this key's exact instant — keys retained to the
//!     same second share one, so the outstanding-lease count grows with the freshness
//!     window rather than with request volume;
//!   * `POST /v3/kv/txn` with `compare { CREATE_REVISION == 0 }` PUTs the key under
//!     that lease IFF it does not yet exist — etcd linearizes the txn, so two racing
//!     inserts cannot both observe the key absent (exactly one `Fresh`).
//!
//! Fail-closed: ANY transport/status/parse error — including a per-operation TIMEOUT —
//! is [`ReplayStoreError::Unavailable`], and an outage is NEVER a fresh nonce.
//!
//! Awaiting the round-trips keeps a runtime worker free but does not bound them: neither
//! `AsyncReplayTier` nor the async serve path times the handler, so a black-holed etcd
//! (a firewall that discards instead of resetting) would park requests and, under
//! `--max-in-flight`, the whole admission budget. The deadline lives in [`wire`], on every POST.

#![cfg(feature = "cpstore_etcd")]

mod gateway;
mod lease_pool;
mod protocol;
#[cfg(test)]
mod test_gateways;
mod wire;

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;

use crate::async_replay::AsyncAtomicReplayStore;
use crate::async_replay::ReplayDecisionFuture;
use crate::async_replay::ReplayInsert;
use crate::shared_replay::ReplayStoreError;
use gateway::GatewayConnector;
use lease_pool::LeasePool;
use protocol::compute_ttl_secs;
use protocol::decision_from_txn;
pub use protocol::system_clock;
pub use protocol::UnixClock;
use wire::Wire;

/// Default per-operation deadline for one etcd gateway round trip.
///
/// This bounds ONE POST, and `atomic_insert_if_absent` issues two (lease grant, txn) —
/// up to four when a lease it reused turns out to have been revoked and the grant and
/// txn are retried once — so the worst case is ~4x this. Two seconds is generous for a
/// same-cluster etcd serving a lease grant and a single-key txn — the point is not to
/// tune latency but to make an unreachable endpoint fail closed in bounded time instead
/// of parking the request forever.
pub const DEFAULT_ETCD_OP_TIMEOUT: Duration = Duration::from_secs(2);

/// Hard ceiling on a configured per-operation timeout. A deadline long enough to outlive
/// the caller's own patience is indistinguishable from having none, so an absurd value is
/// clamped rather than honoured.
pub const MAX_ETCD_OP_TIMEOUT: Duration = Duration::from_secs(30);

/// A durable, CP/linearizable ASYNC authoritative replay store over etcd's v3 JSON
/// gateway. Holds one pooled `hyper` client (cheap to clone per op) and the
/// gateway base URL.
pub struct EtcdAsyncAtomicReplayStore {
    wire: Wire,
    /// The store's own clock, read once per op for the lease-TTL arithmetic.
    clock: UnixClock,
    /// The leases already granted, shared by every nonce retained to the same instant.
    leases: LeasePool,
}

impl EtcdAsyncAtomicReplayStore {
    /// Build a store over the etcd JSON-gateway `base_url` (e.g.
    /// `http://host:2379`) with the production system clock.
    pub fn connect(base_url: &str) -> Result<Self, ReplayStoreError> {
        Self::connect_with(base_url, system_clock())
    }

    /// Build with an injected clock (deterministic tests inject a fixed one).
    pub fn connect_with(base_url: &str, clock: UnixClock) -> Result<Self, ReplayStoreError> {
        Self::connect_with_timeout(base_url, clock, DEFAULT_ETCD_OP_TIMEOUT)
    }

    /// Build with an injected clock and an explicit per-operation deadline. A zero
    /// timeout is refused in the only way this signature allows — it is raised to 1ms —
    /// because `timeout(0)` fires before the request is even issued, which would fail
    /// EVERY insert closed and take the whole serving path down. The value is also
    /// clamped to [`MAX_ETCD_OP_TIMEOUT`].
    pub fn connect_with_timeout(
        base_url: &str,
        clock: UnixClock,
        op_timeout: Duration,
    ) -> Result<Self, ReplayStoreError> {
        let connector = GatewayConnector::for_endpoint(base_url)?;
        let client = Client::builder(TokioExecutor::new()).build(connector);
        let op_timeout = op_timeout.clamp(Duration::from_millis(1), MAX_ETCD_OP_TIMEOUT);
        Ok(EtcdAsyncAtomicReplayStore {
            wire: Wire::new(client, base_url, op_timeout),
            clock,
            leases: LeasePool::new(),
        })
    }

    /// The per-operation deadline in force.
    pub fn op_timeout(&self) -> Duration {
        self.wire.op_timeout()
    }

    /// A lease that expires at `retain_until`: a pooled one when the pool holds one still
    /// live (a lease already granted to expire at this exact instant is the same retention
    /// this key needs, so it is reused rather than duplicated), else a fresh grant.
    /// The flag is whether the lease came from the pool.
    async fn lease_for(
        &self,
        retain_until: i64,
        now: i64,
    ) -> Result<(i64, bool), ReplayStoreError> {
        match self.leases.pooled(retain_until, now) {
            Some(pooled) => Ok((pooled, true)),
            None => Ok((self.grant_pooled(retain_until, now).await?, false)),
        }
    }

    /// Grant a lease that expires at `retain_until` and offer it for reuse.
    async fn grant_pooled(&self, retain_until: i64, now: i64) -> Result<i64, ReplayStoreError> {
        // Bounded lease TTL. Past the staleness guard the window is strictly positive, so
        // the helper's clamp is not load-bearing here.
        let granted = self
            .wire
            .grant_lease(compute_ttl_secs(retain_until, now))
            .await?;
        self.leases.offer(retain_until, granted);
        Ok(granted)
    }

    /// Record `key_b64` as seen, retained to `retain_until`, judged at `now`.
    async fn insert_at(
        &self,
        key_b64: String,
        retain_until: i64,
        now: i64,
    ) -> Result<ReplayDecision, ReplayStoreError> {
        // MCPS-08 defensive pre-store rejection (#142), the guard the Redis backend
        // enforces too.
        //
        // If the (already skew-folded) retain-until is at or before `now`, the request
        // is ALREADY STALE. `compute_ttl_secs` CLAMPS a non-positive window up to a
        // minimal 1s lease, so without this guard an expired nonce would be
        // put-if-absent'd and reported `Fresh` — by the LINEARIZABLE production
        // backend, the one a deployment selects when it wants the strongest replay
        // guarantee. Enforcing it at this layer means an upstream ordering regression
        // (the `mcp-re-core` freshness step no longer running before replay) cannot
        // admit a stale nonce.
        //
        // Same `now` the lease arithmetic uses, so the guard and the granted lease
        // cannot disagree about when it is.
        if crate::shared_replay::is_stale_pre_store(retain_until, now) {
            return Err(ReplayStoreError::Unavailable {
                details: format!(
                    "replay request already stale: retain_until ({retain_until}) is at \
                     or before now ({now}) — rejected pre-store (MCPS-08, fail closed) \
                     rather than recorded as Fresh"
                ),
            });
        }

        let (lease_id, reused) = self.lease_for(retain_until, now).await?;

        // Linearizable put-if-absent under the lease.
        let mut txn = self.wire.put_if_absent(&key_b64, lease_id).await;
        // A pooled lease can be revoked by etcd between the moment it was read and
        // the moment the txn lands (its instant arrives, an operator revokes it),
        // and a put under a lease that no longer exists is refused. That is a stale
        // local optimisation, not an unhealthy store, so it is retried ONCE on a
        // lease this store grants itself. A second failure is the store's answer.
        if txn.is_err() && reused {
            self.leases.forget(retain_until, lease_id);
            let granted = self.grant_pooled(retain_until, now).await?;
            txn = self.wire.put_if_absent(&key_b64, granted).await;
        }
        // A non-fresh outcome leaves this lease holding nothing of THIS request's,
        // and it is not revoked: the lease is offered to every later nonce retained
        // to the same instant, so revoking it would drop keys that belong to other
        // requests a whole freshness window early — a replay hole, not a saving.
        // Nothing accumulates either way, because a lease is granted only when the
        // pool has none for that instant.
        Ok(decision_from_txn(&txn?))
    }
}

impl AsyncAtomicReplayStore for EtcdAsyncAtomicReplayStore {
    fn atomic_insert_if_absent<'a>(&'a self, insert: ReplayInsert<'a>) -> ReplayDecisionFuture<'a> {
        // Retention is an etcd lease TTL, not a bounded local set, so there is no local
        // ceiling to split: `insert.actor` is budgeted above this seam by
        // `AsyncReplayTier`, and the leases themselves are shared per expiry instant
        // (see [`LeasePool`]). Together those decide what one signature-valid peer can
        // make this cluster hold — and holding it to its backend quota raises a NOSPACE
        // alarm that stays raised, read-only, until an operator compacts, defragments
        // and disarms it, taking every co-tenant of that etcd down with the replay tier.
        //
        // Read the store's OWN clock once (the trait's vestigial now_unix=0 is
        // ignored), and reuse it for the lease-TTL arithmetic.
        let now = (self.clock)();
        let key_b64 = STANDARD.encode(insert.key.as_bytes());
        Box::pin(self.insert_at(key_b64, insert.retain_until, now))
    }

    /// A genuinely cross-process, linearizable durable backend (ADR-MCPS-020).
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::Durable
    }
}

#[cfg(test)]
mod tests {
    //! C027/C031 (the missing MCPS-08 pre-store guard) and C044 (the unbounded round
    //! trip). The store holds a concrete `hyper` client rather than an injectable
    //! transport, so these drive it against real local sockets: the guard is proven by
    //! the store never reaching a socket at all, and the timeout by a listener that
    //! accepts and then says nothing.

    use super::test_gateways::counting_gateway;
    use super::test_gateways::ok_json;
    use super::test_gateways::scripted_gateway;
    use super::test_gateways::silent_gateway;
    use super::*;
    use serde_json::Value;

    /// Every entry in these tests is charged to one signer; the per-actor budget
    /// has its own test below.
    const TEST_ACTOR: &str = "did:example:test-signer";
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    const NOW: i64 = 1_779_998_100;

    fn fixed_clock() -> UnixClock {
        Box::new(|| NOW)
    }

    #[tokio::test]
    async fn an_already_stale_request_is_rejected_without_touching_etcd() {
        // retain_until == now is a non-positive remaining window. Before the fix,
        // compute_ttl_secs clamped that up to a 1s lease, the key was put-if-absent'd,
        // and the store answered Fresh — an expired nonce admitted by the LINEARIZABLE
        // backend, the one chosen for the strongest guarantee.
        //
        // The store is pointed at a gateway that accepts connections and counts them, so
        // "no etcd call was made" is asserted rather than assumed: with the guard removed
        // this fails on the accept count as well as on the message.
        let (base, accepts) = silent_gateway().await;
        let store = EtcdAsyncAtomicReplayStore::connect_with_timeout(
            &base,
            fixed_clock(),
            Duration::from_millis(150),
        )
        .expect("an http gateway endpoint is servable");
        let err = store
            .atomic_insert_if_absent(ReplayInsert::new(
                "did:example:host|aud|nonce",
                TEST_ACTOR,
                NOW,
                0,
            ))
            .await
            .expect_err("an already-stale request must never be admitted as Fresh");
        let ReplayStoreError::Unavailable { details } = err;
        assert!(
            details.contains("already stale") && details.contains("MCPS-08"),
            "expected the pre-store staleness rejection, got: {details}"
        );
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            0,
            "no lease/grant or kv/txn may be issued for an already-stale request — it must \
             be rejected BEFORE touching etcd"
        );
    }

    #[tokio::test]
    async fn a_fresh_window_is_bounded_by_the_per_operation_deadline() {
        // C044: the module doc claimed the request path was "bounded by the tier's own
        // timeout". AsyncReplayTier has none, and the async serve path awaits the handler
        // unbounded — so a gateway that accepts and never answers parked the request (and
        // its in-flight admission slot) indefinitely. This must now fail closed, and
        // promptly.
        let (base, accepts) = silent_gateway().await;
        let store = EtcdAsyncAtomicReplayStore::connect_with_timeout(
            &base,
            fixed_clock(),
            Duration::from_millis(150),
        )
        .expect("an http gateway endpoint is servable");
        let started = tokio::time::Instant::now();
        let err = store
            // A comfortably fresh window, so the staleness guard above is not what fires.
            .atomic_insert_if_absent(ReplayInsert::new(
                "did:example:host|aud|nonce-fresh",
                TEST_ACTOR,
                NOW + 300,
                0,
            ))
            .await
            .expect_err("an unanswering gateway must fail closed, not hang");
        let elapsed = started.elapsed();
        let ReplayStoreError::Unavailable { details } = err;
        assert!(
            details.contains("per-operation deadline"),
            "expected the timeout to be the reason, got: {details}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the call must return on its own deadline, took {elapsed:?}"
        );
        assert!(
            accepts.load(Ordering::SeqCst) >= 1,
            "this test must actually have reached the gateway, or it proves nothing about \
             the timeout"
        );
    }

    /// One lease per admitted nonce makes the outstanding-lease count grow with request
    /// VOLUME: a signature-valid peer streaming distinct nonces accumulates leases and
    /// keys until etcd hits its backend quota, whose NOSPACE alarm holds the cluster
    /// read-only until an operator intervenes by hand. Nonces retained to the same
    /// instant want the same expiry, so they share one lease and the count grows with
    /// the freshness window instead.
    #[tokio::test]
    async fn nonces_retained_to_the_same_instant_share_one_lease() {
        let gateway = counting_gateway().await;
        let (base, grants, txns, ttls) = (&gateway.base, &gateway.grants, &gateway.txns, &gateway.ttls);
        let store = EtcdAsyncAtomicReplayStore::connect_with(&base, fixed_clock())
            .expect("an http gateway endpoint is servable");
        for i in 0..25 {
            assert_eq!(
                store
                    .atomic_insert_if_absent(ReplayInsert::new(
                        &format!("did:example:host|aud|nonce-{i}"),
                        TEST_ACTOR,
                        NOW + 300,
                        0,
                    ))
                    .await
                    .expect("the scripted gateway admits every put"),
                ReplayDecision::Fresh
            );
        }
        assert_eq!(
            txns.load(Ordering::SeqCst),
            25,
            "every nonce still gets its own linearizable put-if-absent"
        );
        assert_eq!(
            grants.load(Ordering::SeqCst),
            1,
            "25 nonces expiring at one instant must not mint 25 leases"
        );

        // A different retain-until is different retention, so it gets its own lease.
        store
            .atomic_insert_if_absent(ReplayInsert::new(
                "did:example:host|aud|later",
                TEST_ACTOR,
                NOW + 600,
                0,
            ))
            .await
            .expect("records");
        assert_eq!(grants.load(Ordering::SeqCst), 2);
        assert_eq!(
            *ttls.lock().expect("ttls"),
            vec![300, 600],
            "each lease is granted for retain_until minus the injected clock"
        );
    }

    fn divergence(secs: i64) -> crate::config_state::ReplicaClockDivergence {
        crate::config_state::ReplicaClockDivergence::new(secs).expect("inside the declared ceiling")
    }

    /// The lease is granted the declared bound longer than the verifier's horizon, and a
    /// replica whose clock runs ahead by that bound still retains to the TRUE horizon.
    #[tokio::test]
    async fn a_lease_outlives_the_horizon_by_the_declared_divergence() {
        let gateway = counting_gateway().await;
        let (base, ttls) = (&gateway.base, &gateway.ttls);
        let store =
            EtcdAsyncAtomicReplayStore::connect_with(&base, divergence(7).retention_clock(|| NOW))
                .expect("an http gateway endpoint is servable");
        store
            .atomic_insert_if_absent(ReplayInsert::new("k|a|n1", TEST_ACTOR, NOW + 300, 0))
            .await
            .expect("records");
        assert_eq!(*ttls.lock().expect("ttls"), vec![307]);

        let ahead = 4;
        let gateway = counting_gateway().await;
        let (base, ttls) = (&gateway.base, &gateway.ttls);
        let fast = EtcdAsyncAtomicReplayStore::connect_with(
            &base,
            divergence(ahead).retention_clock(move || NOW + ahead),
        )
        .expect("an http gateway endpoint is servable");
        fast.atomic_insert_if_absent(ReplayInsert::new("k|a|n2", TEST_ACTOR, NOW + 300, 0))
            .await
            .expect("records");
        assert!(
            ttls.lock().expect("ttls")[0] >= 300,
            "the lease lapses before the horizon, 300s after true now"
        );
    }

    /// The pool holds leases only while they are live: one whose instant has passed has
    /// been revoked by etcd, and attaching a key to it would leave the key unretained.
    #[tokio::test]
    async fn an_expired_lease_is_never_reused() {
        let gateway = counting_gateway().await;
        let (base, grants) = (&gateway.base, &gateway.grants);
        let store = EtcdAsyncAtomicReplayStore::connect_with(&base, fixed_clock())
            .expect("an http gateway endpoint is servable");
        store
            .atomic_insert_if_absent(ReplayInsert::new("k|a|n1", TEST_ACTOR, NOW + 5, 0))
            .await
            .expect("records");
        assert_eq!(grants.load(Ordering::SeqCst), 1);
        assert_eq!(store.leases.pooled(NOW + 5, NOW), Some(1));
        // Past that instant the lease is gone from etcd, so it is gone from the pool.
        assert_eq!(store.leases.pooled(NOW + 5, NOW + 5), None);
        assert!(
            store.leases.is_empty(),
            "an expired lease must not be kept for reuse"
        );
    }

    #[test]
    fn the_operation_timeout_is_clamped_at_both_ends() {
        // Zero would make timeout() fire before the request is issued, failing EVERY
        // insert closed and taking the serving path down; an absurd value is
        // indistinguishable from no deadline at all.
        let zero = EtcdAsyncAtomicReplayStore::connect_with_timeout(
            "http://127.0.0.1:2379",
            fixed_clock(),
            Duration::ZERO,
        )
        .expect("an http gateway endpoint is servable");
        assert_eq!(
            zero.op_timeout(),
            Duration::from_millis(1),
            "zero is raised, not honoured"
        );

        let absurd = EtcdAsyncAtomicReplayStore::connect_with_timeout(
            "http://127.0.0.1:2379",
            fixed_clock(),
            Duration::from_secs(86_400),
        )
        .expect("an http gateway endpoint is servable");
        assert_eq!(
            absurd.op_timeout(),
            MAX_ETCD_OP_TIMEOUT,
            "clamped to the ceiling"
        );

        let default = EtcdAsyncAtomicReplayStore::connect("http://127.0.0.1:2379")
            .expect("an http gateway endpoint is servable");
        assert_eq!(
            default.op_timeout(),
            DEFAULT_ETCD_OP_TIMEOUT,
            "connect() is bounded too"
        );
    }

    /// One etcd cluster behind two stores: the gateway applies the put-if-absent compare
    /// to a shared key set, so the first store to put a key gets `succeeded` and every
    /// later put of it — through either store — does not. A nonce admitted through one
    /// replica is a replay through the same replica and through another.
    #[tokio::test]
    async fn a_nonce_admitted_through_one_store_is_a_replay_through_another() {
        let keys = Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::new()));
        let base = scripted_gateway(Arc::new(move |path: &str, request: &Value| {
            if path == "/v3/lease/grant" {
                return ok_json(r#"{"ID":"7","TTL":"300"}"#);
            }
            let key = request["compare"][0]["key"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let fresh = keys.lock().expect("keys").insert(key);
            ok_json(&format!("{{\"succeeded\":{fresh}}}"))
        }))
        .await;
        let a = EtcdAsyncAtomicReplayStore::connect_with(&base, fixed_clock()).expect("servable");
        let b = EtcdAsyncAtomicReplayStore::connect_with(&base, fixed_clock()).expect("servable");
        let insert = || ReplayInsert::new("did:example:host|aud|nonce", TEST_ACTOR, NOW + 300, 0);

        assert_eq!(
            a.atomic_insert_if_absent(insert()).await.expect("answered"),
            ReplayDecision::Fresh,
            "first sight is fresh"
        );
        assert_eq!(
            a.atomic_insert_if_absent(insert()).await.expect("answered"),
            ReplayDecision::Replay,
            "the same replica must reject it"
        );
        assert_eq!(
            b.atomic_insert_if_absent(insert()).await.expect("answered"),
            ReplayDecision::Replay,
            "a second replica against the same cluster must reject it"
        );
    }

    /// An outage is never a fresh nonce: a gateway that answers every POST with a
    /// server error fails the insert closed.
    #[tokio::test]
    async fn a_gateway_that_answers_an_error_status_is_unavailable_never_fresh() {
        let base = scripted_gateway(Arc::new(|_: &str, _: &Value| {
            "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                .to_string()
        }))
        .await;
        let store =
            EtcdAsyncAtomicReplayStore::connect_with(&base, fixed_clock()).expect("servable");
        let err = store
            .atomic_insert_if_absent(ReplayInsert::new("k|a|n", TEST_ACTOR, NOW + 300, 0))
            .await
            .expect_err("an erroring gateway must fail closed");
        let ReplayStoreError::Unavailable { details } = err;
        assert!(
            details.contains("503"),
            "the status is the reason: {details}"
        );
    }

    /// A gateway that answers a redirect is not followed: its target is never reached,
    /// and the 3xx body — shaped like a successful grant and compare — is never read as
    /// an etcd decision.
    #[tokio::test]
    async fn a_redirecting_gateway_is_refused_and_its_target_never_reached() {
        let (elsewhere, reached) = silent_gateway().await;
        let base = scripted_gateway(Arc::new(move |path: &str, _: &Value| {
            const BODY: &str = r#"{"ID":"424242","succeeded":true}"#;
            format!(
                "HTTP/1.1 302 Found\r\nlocation: {elsewhere}{path}\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n{BODY}",
                BODY.len()
            )
        }))
        .await;
        let store =
            EtcdAsyncAtomicReplayStore::connect_with(&base, fixed_clock()).expect("servable");
        let result = store
            .atomic_insert_if_absent(ReplayInsert::new("k|a|n", TEST_ACTOR, NOW + 300, 0))
            .await;
        assert!(
            matches!(result, Err(ReplayStoreError::Unavailable { .. })),
            "a redirecting gateway must fail closed, got {result:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            reached.load(Ordering::SeqCst),
            0,
            "the redirect target was connected to"
        );
    }

    /// LOAD-BEARING (Owner Ruling 6): `--cpstore-etcd-endpoint` is operator-supplied, and a
    /// WELL-FORMED URL is exactly the shape that carries a password — the shape check is
    /// not the boundary. The request-build failure names the crate-internal PATH, which no
    /// operator input reaches, and says nothing about the endpoint at all: a projection
    /// would render `<unparseable>` here for every reachable failure, since `Request::
    /// builder().uri()` and the projection share one parser, and printing the endpoint's
    /// path would reinstate the exposure for a credential carried as a path segment.
    #[tokio::test]
    async fn a_request_build_failure_leaks_neither_the_credential_nor_the_configured_url() {
        const CONFIGURED: &str = "http://ops:hunter2@etcd internal:2379";
        let client = Client::builder(TokioExecutor::new())
            .build(GatewayConnector::for_endpoint("http://127.0.0.1:1").expect("servable"));
        let err =
            wire::exchange(&client, CONFIGURED, "/v3/kv/txn", &Value::Null)
                .await
                .expect_err("a URI hyper cannot parse must not build a request");
        let ReplayStoreError::Unavailable { details } = err;
        assert!(
            !details.contains("hunter2"),
            "the configured password reached the diagnostic: {details}"
        );
        assert!(
            !details.contains(CONFIGURED) && !details.contains("etcd internal"),
            "the complete configured endpoint was echoed: {details}"
        );
        assert!(
            details.contains("build etcd request"),
            "an operator still learns which stage failed: {details}"
        );
    }

    /// The positive control for the redaction above: it changed what a failure SAYS, not
    /// which endpoints are usable. A credential-bearing endpoint that parses must still
    /// build its request and fail (if at all) at the transport, not at the builder.
    #[tokio::test]
    async fn a_well_formed_credential_bearing_endpoint_still_reaches_the_transport() {
        let client = Client::builder(TokioExecutor::new())
            .build(GatewayConnector::for_endpoint("http://127.0.0.1:1").expect("servable"));
        let err = wire::exchange(
            &client,
            "http://ops:hunter2@127.0.0.1:1",
            "/v3/kv/txn",
            &Value::Null,
        )
        .await
        .expect_err("nothing is listening on port 1");
        let ReplayStoreError::Unavailable { details } = err;
        assert!(
            !details.contains("build etcd request"),
            "a well-formed endpoint must reach the transport, not be refused here: {details}"
        );
    }
}
