// SPDX-License-Identifier: Apache-2.0
//! G1: commit one admitted exchange's execution intent, and redeem the witness, before it is
//! dispatched (ADR-MCPRE-070 §4, D7, D9, D12).
//!
//! ```text
//! coordinate (the exchange's request.accepted)  ── None ──────────────> 500, nothing produced
//!   └─ ExecutionIntent::produce                  ── identity failure ──> 500
//!        └─ EstablishedProvider::commit::<Intent> ── Rejected ─────────> 500
//!             │                                   ── Unavailable ──────> 503
//!             │                                   ── Uncertain ────────> 503
//!             └─ CommitmentWitness::redeem        ── refused ──────────> 500
//!                  └─ Redeemed<Intent>: the crossing may proceed
//! ```
//!
//! One bounded attempt, no retry loop. Every failure is a refusal BEFORE the backend is
//! reached, so it is free of execution: the token says a required commitment could not be
//! established, and the exchange machine's disposition says what that means for a retry.
//! The status says whether a retry on this replica can succeed — 503 where the provider's
//! condition can change, 500 where it cannot (the `retention/refusal.rs` precedent).
//!
//! The provider's future runs inside the request's own future, so dropping the request
//! cancels the commit and leaves nothing to dispatch: W2 (§6). An `Uncertain` intent keeps
//! its identity "possibly committed", and no other bytes are ever produced under it,
//! because the event is dropped with the exchange.

use std::sync::Arc;
use std::time::Duration;

use mcp_re_core::McpReError;

use crate::audit_record::{AuditRecord, ExchangeCoordinate, ExecutionIntent};
use crate::refusal::Refusal;

use super::outcome::CommittedOutcome;
use super::{CommitmentBound, CommitmentFailure, EstablishedProvider, Intent, Redeemed};

/// The required posture's crossings: an established provider that may serve them, and how
/// long the request path waits for each. G1 is here; G2 is [`super::outcome`].
#[derive(Debug)]
pub(super) struct IntentCommitment {
    provider: Arc<EstablishedProvider>,
    bound: CommitmentBound,
}

impl IntentCommitment {
    /// Intents committed to `provider` within `bound`, or `None` when the provider's declared
    /// tier cannot serve the required posture (D3): not even a test runs the required
    /// posture over a volatile tier.
    #[cfg(any(test, feature = "audit_commitment_reference"))]
    pub(super) fn over(provider: Arc<EstablishedProvider>, bound: CommitmentBound) -> Option<Self> {
        provider
            .meets_required_minimum()
            .then_some(IntentCommitment { provider, bound })
    }

    /// The longest this crossing can hold the request before dispatch.
    pub(super) fn wait(&self) -> Duration {
        self.bound.get()
    }

    /// G1 for the exchange `coordinate` names.
    ///
    /// `coordinate` is what the exchange's `request.accepted` established (D9). `None` means
    /// no accepted event could be numbered — no run could be drawn, or the run is exhausted —
    /// and an intent with no exchange to name is never produced or fabricated.
    pub(super) async fn commit(
        &self,
        coordinate: Option<ExchangeCoordinate>,
        intent: ExecutionIntent<'_>,
    ) -> Result<Redeemed<Intent>, Refusal> {
        let coordinate = coordinate.ok_or_else(cannot_commit)?;
        let event = intent.produce(coordinate).map_err(|_| cannot_commit())?;
        let witness = self
            .provider
            .commit::<Intent>(&event, self.bound)
            .await
            .map_err(|failure| refusal_for(&failure))?;
        witness
            .redeem(&event, &self.provider)
            .map_err(|_| cannot_commit())
    }
}

impl IntentCommitment {
    /// G2 for this exchange, over the provider and bound G1 used.
    pub(super) async fn outcome(
        &self,
        coordinate: Option<ExchangeCoordinate>,
        observed: AuditRecord,
    ) -> Result<CommittedOutcome, Refusal> {
        super::outcome::commit(&self.provider, self.bound, coordinate, observed).await
    }
}

/// A commitment that a retry on this replica cannot establish either.
fn cannot_commit() -> Refusal {
    Refusal::new(McpReError::AuditCommitmentUnavailable, 500)
}

/// What a failed commitment is answered with: one decision, in one place.
///
/// A provider that was unavailable, out of capacity or uncertain may answer a retry, so 503.
/// A provider that refused this event will refuse it again, so 500: telling a client to keep
/// retrying a replica whose provider rejects it is the wrong advice.
fn refusal_for(failure: &CommitmentFailure) -> Refusal {
    match failure {
        CommitmentFailure::Rejected(_) => cannot_commit(),
        CommitmentFailure::Unavailable | CommitmentFailure::Uncertain(_) => {
            Refusal::new(McpReError::AuditCommitmentUnavailable, 503)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_commitment::reference::{Forgery, ReferenceAuthority, Step};
    use crate::audit_commitment::{DurabilityTier, RejectReason, UncertainCause};
    use crate::audit_record::{
        AuditEnvelope, AuditRecord, AuditSubject, EventAllocator, EventScope, RunId,
    };

    fn bound(ms: u64) -> CommitmentBound {
        CommitmentBound::new(Duration::from_millis(ms)).expect("a legal bound")
    }

    fn reference(steps: impl IntoIterator<Item = Step>) -> Arc<ReferenceAuthority> {
        Arc::new(ReferenceAuthority::new(DurabilityTier::SurvivesProxyProcessLoss).scripted(steps))
    }

    fn crossing(authority: &Arc<ReferenceAuthority>, ms: u64) -> IntentCommitment {
        let authority: Arc<dyn super::super::CommitmentAuthority> = authority.clone();
        IntentCommitment::over(EstablishedProvider::establish(authority), bound(ms))
            .expect("an eligible tier")
    }

    /// A real accepted event, so the coordinate is one the process allocator produced.
    fn coordinate() -> ExchangeCoordinate {
        crate::audit_record::record_to(
            &None,
            None,
            AuditSubject::request_accepted(
                &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                crate::admission_enforcer::AdmissionFacet::NotConfigured,
            ),
            Some("actor-a".into()),
            200,
            10,
        )
        .expect("the process run is drawn in a test build")
    }

    fn unavailable(status: u16) -> Refusal {
        Refusal::new(McpReError::AuditCommitmentUnavailable, status)
    }

    async fn run(authority: &Arc<ReferenceAuthority>) -> Result<Redeemed<Intent>, Refusal> {
        crossing(authority, 200)
            .commit(Some(coordinate()), ExecutionIntent::new("actor-a", 10))
            .await
    }

    #[tokio::test]
    async fn commit_gives_a_redeemed_intent_for_this_exchange() {
        let authority = reference([Step::Commit]);
        let coordinate = coordinate();
        let redeemed = crossing(&authority, 200)
            .commit(Some(coordinate), ExecutionIntent::new("actor-a", 10))
            .await
            .expect("committed");
        let journaled = authority.journaled();
        assert_eq!(journaled.len(), 1, "exactly one event was committed");
        assert_eq!(journaled[0].0, redeemed.binding().id());
        assert_eq!(
            journaled[0].1,
            Some(coordinate),
            "the intent names its exchange"
        );
        assert_eq!(redeemed.tier(), DurabilityTier::SurvivesProxyProcessLoss);
    }

    #[tokio::test]
    async fn a_rejected_intent_is_500() {
        let refused = run(&reference([Step::Reject(RejectReason::Refused)])).await;
        assert_eq!(refused.map(|_| ()), Err(unavailable(500)));
    }

    #[tokio::test]
    async fn an_unavailable_provider_is_503() {
        assert_eq!(
            run(&reference([Step::Unavailable])).await.map(|_| ()),
            Err(unavailable(503))
        );
    }

    #[tokio::test]
    async fn a_provider_that_never_answers_times_out_within_the_bound_as_503() {
        let started = std::time::Instant::now();
        let refused = tokio::time::timeout(
            Duration::from_secs(5),
            crossing(&reference([Step::Hang]), 50)
                .commit(Some(coordinate()), ExecutionIntent::new("actor-a", 10)),
        )
        .await
        .expect("the bound fires before the outer guard");
        assert_eq!(refused.map(|_| ()), Err(unavailable(503)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_dropped_completion_is_503() {
        assert_eq!(
            run(&reference([Step::DropCompletion])).await.map(|_| ()),
            Err(unavailable(503))
        );
    }

    #[tokio::test]
    async fn a_panicking_provider_is_503_and_does_not_unwind() {
        assert_eq!(
            run(&reference([Step::PanicInPoll])).await.map(|_| ()),
            Err(unavailable(503))
        );
    }

    /// A receipt for another crossing, another event, or the previous commit is not THIS
    /// commitment: the owner's checks refuse it, and the crossing does not proceed.
    #[tokio::test]
    async fn a_forged_or_stale_receipt_is_503() {
        for step in [Step::Forge(Forgery::Crossing), Step::Forge(Forgery::Tier)] {
            assert_eq!(
                run(&reference([step])).await.map(|_| ()),
                Err(unavailable(503))
            );
        }
        let authority = reference([Step::Commit, Step::ReplayPrevious]);
        run(&authority).await.expect("the first commits");
        assert_eq!(run(&authority).await.map(|_| ()), Err(unavailable(503)));
    }

    /// D9: with no accepted event there is no exchange to name, so nothing is produced and
    /// the provider is never asked.
    #[tokio::test]
    async fn an_absent_coordinate_is_500_and_asks_nothing() {
        let authority = reference([]);
        let refused = crossing(&authority, 200)
            .commit(None, ExecutionIntent::new("actor-a", 10))
            .await;
        assert_eq!(refused.map(|_| ()), Err(unavailable(500)));
        assert_eq!(authority.requests(), 0);
    }

    /// The intent is produced in the exchange's run, so a coordinate the process allocator
    /// did not issue — another run — names no exchange, and nothing is committed.
    #[tokio::test]
    async fn a_coordinate_from_another_run_is_500_and_asks_nothing() {
        let foreign = AuditEnvelope::produce_for_test(
            &EventAllocator::starting_at(RunId::fixed([0x77; 16]), 0),
            None,
            AuditRecord {
                subject: AuditSubject::request_accepted(
                    &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                    crate::admission_enforcer::AdmissionFacet::NotConfigured,
                ),
                actor_id: None,
                status: 200,
                at_unix: 1,
            },
        )
        .expect("produced");
        assert_eq!(foreign.scope(), EventScope::Origin);
        let authority = reference([]);
        let refused = crossing(&authority, 200)
            .commit(foreign.exchange_coordinate(), ExecutionIntent::new("a", 1))
            .await;
        assert_eq!(refused.map(|_| ()), Err(unavailable(500)));
        assert_eq!(authority.requests(), 0);
    }

    /// The status split is one decision: a provider whose answer can change earns 503, one
    /// that refused this event earns 500, and every failure carries the one token.
    #[test]
    fn each_failure_class_earns_its_own_status() {
        assert_eq!(
            refusal_for(&CommitmentFailure::Rejected(RejectReason::IdentityConflict)),
            unavailable(500)
        );
        assert_eq!(
            refusal_for(&CommitmentFailure::Unavailable),
            unavailable(503)
        );
        for cause in [
            UncertainCause::TimedOut,
            UncertainCause::Cancelled,
            UncertainCause::ProviderPanicked,
        ] {
            assert_eq!(
                refusal_for(&CommitmentFailure::Uncertain(cause)),
                unavailable(503)
            );
        }
    }

    /// D3 holds for the crossing too: a volatile provider cannot serve it.
    #[test]
    fn a_volatile_provider_cannot_serve_the_crossing() {
        let volatile: Arc<dyn super::super::CommitmentAuthority> =
            Arc::new(ReferenceAuthority::new(DurabilityTier::ProcessVolatile));
        assert!(
            IntentCommitment::over(EstablishedProvider::establish(volatile), bound(10)).is_none()
        );
    }
}
