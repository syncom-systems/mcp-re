// SPDX-License-Identifier: Apache-2.0
//! G2: commit one exchange's observed outcome before its success is visible (ADR-MCPRE-070
//! §4, D1, D4, D8, Q2).
//!
//! ```text
//! coordinate (the exchange's request.accepted)      ── None ──────────────> 500, nothing produced
//!   └─ produce response.signed, scope Exchange(c)    ── identity failure ──> 500
//!        └─ EstablishedProvider::commit::<Outcome>   ── any failure ───────> 500
//!             └─ CommitmentWitness::redeem           ── refused ───────────> 500
//!                  └─ CommittedOutcome: retention may complete, then the success is served
//! ```
//!
//! The outcome is the `response.signed` event the observer is offered when the response is
//! served (D1: no outcome token). It is produced and committed here, BEFORE retention
//! completes (Q2), and offered later as the same bytes, so the observed line and the
//! committed event are one event with one identity. A committed outcome states what the
//! proxy observed and signed; it never states that the response was served — retention can
//! still fail after it (W5b), and then the client is refused.
//!
//! Every failure is 500, never 503: the backend may already have acted, and 503 is the status
//! clients retry. The exchange machine's disposition (`PossiblyExecuted`) says what a retry
//! means. That is where G2 differs from G1, whose refusals are free of execution.
//!
//! One bounded attempt. The envelope is produced once, so a provider's internal retry resends
//! identical bytes, and an `Uncertain` outcome keeps its identity "possibly committed".

use std::sync::Arc;

use mcp_re_core::McpReError;

use crate::audit_record::{AuditEnvelope, AuditRecord, ExchangeCoordinate};
use crate::refusal::Refusal;

use super::{CommitmentBound, EstablishedProvider, Outcome, Redeemed};

/// An exchange's outcome, committed and redeemed for exactly the event the observer will be
/// offered. Constructed only by [`commit`]: holding one is the proof.
#[derive(Debug)]
pub(crate) struct CommittedOutcome {
    envelope: AuditEnvelope,
    /// Never read: what it proves is that [`commit`] redeemed a witness for `envelope`.
    _redeemed: Redeemed<Outcome>,
}

impl CommittedOutcome {
    /// The committed `response.signed` event, which the success exit offers unchanged.
    pub(crate) fn envelope(&self) -> &AuditEnvelope {
        &self.envelope
    }
}

/// G2 for the exchange `coordinate` names, over `observed`: the record of the response this
/// exchange is about to serve, at its actual status (200, or 202 for an acknowledgement).
pub(super) async fn commit(
    provider: &Arc<EstablishedProvider>,
    bound: CommitmentBound,
    coordinate: Option<ExchangeCoordinate>,
    observed: AuditRecord,
) -> Result<CommittedOutcome, Refusal> {
    let coordinate = coordinate.ok_or_else(cannot_commit)?;
    let envelope =
        crate::audit_record::produce(Some(coordinate), observed).map_err(|_| cannot_commit())?;
    let witness = provider
        .commit::<Outcome>(envelope.event(), bound)
        .await
        .map_err(|_| cannot_commit())?;
    let redeemed = witness
        .redeem(envelope.event(), provider)
        .map_err(|_| cannot_commit())?;
    Ok(CommittedOutcome {
        envelope,
        _redeemed: redeemed,
    })
}

/// Every G2 refusal, whatever the provider answered.
pub(super) fn cannot_commit() -> Refusal {
    Refusal::new(McpReError::AuditCommitmentUnavailable, 500)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::audit_commitment::reference::{Forgery, ReferenceAuthority, Step};
    use crate::audit_commitment::{DurabilityTier, RejectReason};
    use crate::audit_record::{AuditSubject, EventScope};

    fn provider(
        steps: impl IntoIterator<Item = Step>,
    ) -> (Arc<ReferenceAuthority>, Arc<EstablishedProvider>) {
        let authority = Arc::new(
            ReferenceAuthority::new(DurabilityTier::SurvivesProxyProcessLoss).scripted(steps),
        );
        (
            authority.clone(),
            EstablishedProvider::eligible_for_test(authority),
        )
    }

    fn bound(ms: u64) -> CommitmentBound {
        CommitmentBound::new(Duration::from_millis(ms)).expect("a legal bound")
    }

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

    fn observed(status: u16) -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::response_signed(),
            actor_id: Some("actor-a".into()),
            status,
            at_unix: 10,
        }
    }

    async fn run(steps: impl IntoIterator<Item = Step>) -> Result<CommittedOutcome, Refusal> {
        let (_, provider) = provider(steps);
        tokio::time::timeout(
            Duration::from_secs(5),
            commit(&provider, bound(50), Some(coordinate()), observed(200)),
        )
        .await
        .expect("the commitment bound fires before the outer guard")
    }

    /// The committed outcome is the response record at its actual status, scoped to this
    /// exchange, and the event the authority journaled is the one the observer will be given.
    #[tokio::test]
    async fn outcome_commit_gives_committed_with_the_actual_status() {
        for status in [200, 202] {
            let (authority, provider) = provider([Step::Commit]);
            let c = coordinate();
            let committed = commit(&provider, bound(200), Some(c), observed(status))
                .await
                .expect("committed");
            let envelope = committed.envelope();
            assert_eq!(envelope.record().status, status);
            assert_eq!(
                envelope.record().event().event_type(),
                "mcp-re.response.signed"
            );
            assert_eq!(envelope.scope(), EventScope::Exchange(c));
            assert_eq!(
                authority.journaled(),
                vec![(envelope.id(), Some(c))],
                "exactly this event was committed, naming its exchange"
            );
        }
    }

    /// Every failure the authority can produce is the same 500, whatever G1 would answer.
    #[tokio::test]
    async fn every_outcome_failure_is_500() {
        for step in [
            Step::Reject(RejectReason::Refused),
            Step::Unavailable,
            Step::Hang,
            Step::DropCompletion,
            Step::PanicInPoll,
            Step::PanicBeforeFuture,
            Step::Forge(Forgery::Crossing),
            Step::Forge(Forgery::Tier),
        ] {
            let refused = run([step]).await.map(|_| ());
            assert_eq!(refused, Err(cannot_commit()));
            assert_eq!(cannot_commit().status, 500);
            assert_eq!(cannot_commit().execution_refinement, None);
        }
    }

    /// No coordinate: nothing is produced and the authority is asked nothing.
    #[tokio::test]
    async fn an_absent_coordinate_is_500_and_asks_nothing() {
        let (authority, provider) = provider([Step::Commit]);
        let refused = commit(&provider, bound(50), None, observed(200)).await;
        assert_eq!(refused.map(|_| ()), Err(cannot_commit()));
        assert_eq!(authority.requests(), 0);
    }

    /// A witness for the intent crossing is not an outcome: the authority's receipt names the
    /// crossing, and a receipt for the other one is refused at mint.
    #[tokio::test]
    async fn an_intent_receipt_does_not_commit_an_outcome() {
        assert_eq!(
            run([Step::Forge(Forgery::Crossing)]).await.map(|_| ()),
            Err(cannot_commit())
        );
    }
}
