// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "redis_replay")]
//! The measured deployment: an admission authority and two sibling replicas, each on its own
//! connection to the one shared store, and the steps the measurement takes over them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mcp_re_http_profile::AdmissionClaims;
use mcp_re_http_profile::AdmissionStatus;
use mcp_re_proxy::admission_source::AsyncAdmissionSource;
use mcp_re_proxy::redis_admission_source::RedisAdmissionSource;
use mcp_re_proxy::HttpProfileProxy;

use super::fixtures::{
    admission_claims, record_verifier, replica, served_of, signed_call, signed_state, NOW,
};

/// One replica and the number of calls that reached its backend.
struct Replica {
    proxy: HttpProfileProxy,
    backend_calls: Arc<AtomicUsize>,
}

impl Replica {
    /// A replica reading the shared store over its own connection.
    async fn connect(url: &str, name: &str) -> Self {
        let source = RedisAdmissionSource::connect(url, record_verifier())
            .await
            .unwrap_or_else(|e| panic!("{name} connects: {e:?}"));
        let backend_calls = Arc::new(AtomicUsize::new(0));
        let proxy = replica(
            Arc::new(source) as Arc<dyn AsyncAdmissionSource>,
            Arc::clone(&backend_calls),
        );
        Self {
            proxy,
            backend_calls,
        }
    }

    /// The status of a call under `claims`, carrying a nonce nobody has used: the replay
    /// tier is real, and a reused nonce would measure its refusal instead of the
    /// revocation's.
    async fn status_of(&self, claims: &AdmissionClaims, nonce: &str) -> u16 {
        self.proxy
            .handle(served_of(&signed_call(claims, nonce)), NOW)
            .await
            .status
    }

    async fn status_of_fresh_call(&self, claims: &AdmissionClaims) -> u16 {
        self.status_of(claims, &mcp_re_test_paths::unique_test_nonce())
            .await
    }

    fn backend_calls(&self) -> usize {
        self.backend_calls.load(Ordering::SeqCst)
    }
}

/// How a revocation reached a sibling: how long it took, and how many requests asked.
pub(super) struct Propagation {
    pub(super) elapsed: Duration,
    pub(super) attempts: usize,
}

/// The authority that writes, and the two replicas that read.
pub(super) struct Fleet {
    authority: RedisAdmissionSource,
    replica_a: Replica,
    replica_b: Replica,
    workload: String,
    claims: AdmissionClaims,
}

impl Fleet {
    /// Three independent connections: the authority that writes, and one per replica that
    /// reads. A single shared connection would measure a memory write. The workload is
    /// published as admitted before the replicas start.
    pub(super) async fn start(url: &str, workload: String) -> Self {
        let authority = RedisAdmissionSource::connect(url, record_verifier())
            .await
            .expect("authority connects");
        let fleet = Self {
            authority,
            replica_a: Replica::connect(url, "A").await,
            replica_b: Replica::connect(url, "B").await,
            claims: admission_claims(&workload, 5),
            workload,
        };
        fleet.publish(1, AdmissionStatus::Admitted).await;
        fleet
    }

    async fn publish(&self, revision: u64, status: AdmissionStatus) {
        self.authority
            .publish(
                &signed_state(&self.workload, 5, revision, status),
                &self.workload,
                NOW,
            )
            .await
            .expect("the store answers")
            .expect("the authority's record is accepted");
    }

    /// Baseline: BOTH replicas serve the workload. Without this the measurement could not
    /// tell a working revocation from a replica that was never admitting the call in the
    /// first place.
    pub(super) async fn assert_both_replicas_admit(&self) {
        let served = self.replica_a.status_of_fresh_call(&self.claims).await;
        assert_eq!(served, 200, "replica A must admit before the revocation");
        let served = self.replica_b.status_of_fresh_call(&self.claims).await;
        assert_eq!(served, 200, "replica B must admit before the revocation");
        assert_eq!(self.replica_a.backend_calls(), 1);
        assert_eq!(self.replica_b.backend_calls(), 1);
    }

    /// The authority revokes. Nothing notifies either replica. The generation is UNCHANGED
    /// — revocation is not a rotation — and the publication sequence advances, which is
    /// what the two counters are for.
    pub(super) async fn revoke(&self) -> Instant {
        let revoked_at = Instant::now();
        self.publish(2, AdmissionStatus::Revoked).await;
        revoked_at
    }

    /// Poll replica B — which performed no revocation and shares nothing with the
    /// authority but the store — until it refuses. Each attempt carries a fresh nonce so
    /// the replay tier never answers instead of the admission gate. Panics when the
    /// refusal has not arrived within `declared_p_ms`.
    pub(super) async fn poll_sibling_until_refused(
        &self,
        revoked_at: Instant,
        declared_p_ms: u128,
    ) -> Propagation {
        let mut attempts = 0usize;
        loop {
            attempts += 1;
            let nonce = format!("n-poll-{attempts}");
            if self.replica_b.status_of(&self.claims, &nonce).await != 200 {
                return Propagation {
                    elapsed: revoked_at.elapsed(),
                    attempts,
                };
            }
            assert!(
                revoked_at.elapsed().as_millis() < declared_p_ms,
                "replica B still served the workload {}ms after it was revoked \
                 (declared P bound {declared_p_ms}ms); propagation did NOT meet the budget",
                revoked_at.elapsed().as_millis(),
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// The refusal must be the admission gate's, not a side effect: the backend never ran
    /// for the revoked call. And replica A, which served it happily a moment ago, now
    /// refuses too.
    pub(super) async fn assert_the_revocation_holds_everywhere(&self) {
        assert_eq!(
            self.replica_b.backend_calls(),
            1,
            "only the pre-revocation call reached the backend on replica B"
        );
        let served = self.replica_a.status_of_fresh_call(&self.claims).await;
        assert_ne!(served, 200, "replica A must honour the revocation as well");
        assert_eq!(self.replica_a.backend_calls(), 1);
    }
}
