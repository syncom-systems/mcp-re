// SPDX-License-Identifier: Apache-2.0
//! G2: commit one exchange's observed outcome before its success is visible (ADR-MCPRE-070
//! §4, D1, D4, D8, Q2).
//!
//! ```text
//! OwedOutcome (G1's: provider, bound, coordinate)
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
//!
//! G2 reads nothing G1 already decided. A committed intent carries its [`OwedOutcome`]: the
//! provider and bound the intent was committed under, and the coordinate it named (D9). So
//! the outcome is committed for the same exchange and to the same provider by construction,
//! and neither the posture nor the coordinate is read again.

use std::sync::Arc;

use mcp_re_core::McpReError;

use crate::audit_record::{AuditEnvelope, AuditRecord, ExchangeCoordinate};
use crate::refusal::Refusal;
use crate::request_stages::{IntentDisposition, OutcomeDisposition};

use super::{CommitmentBound, EstablishedProvider, Intent, Outcome, Redeemed};

/// What a committed intent owes at G2: its outcome, committed to the provider and within the
/// bound the intent was, for the exchange the intent named. Made only by G1, so holding one is
/// the proof the outcome is owed; [`commit`](Self::commit) spends it.
#[derive(Debug)]
pub(crate) struct OwedOutcome {
    provider: Arc<EstablishedProvider>,
    bound: CommitmentBound,
    coordinate: ExchangeCoordinate,
    /// Never read: what it proves is that G1 redeemed this exchange's intent.
    _intent: Redeemed<Intent>,
}

impl OwedOutcome {
    /// The outcome G1 leaves owed after redeeming `intent` for `coordinate` on `provider`.
    pub(super) fn new(
        provider: Arc<EstablishedProvider>,
        bound: CommitmentBound,
        coordinate: ExchangeCoordinate,
        intent: Redeemed<Intent>,
    ) -> Self {
        OwedOutcome {
            provider,
            bound,
            coordinate,
            _intent: intent,
        }
    }

    /// The intent G1 redeemed. Tests read it.
    #[cfg(test)]
    pub(super) fn intent(&self) -> &Redeemed<Intent> {
        &self._intent
    }

    /// G2 over `observed`: the record of the response this exchange is about to serve, at its
    /// actual status (200, or 202 for an acknowledgement).
    pub(crate) async fn commit(self, observed: AuditRecord) -> Result<CommittedOutcome, Refusal> {
        commit(&self.provider, self.bound, self.coordinate, observed).await
    }
}

impl IntentDisposition {
    /// G2: what this exchange's success may be published with (§4, D4, Q2).
    ///
    /// Requiredness is the state G1 carried across the dispatch, never the posture read
    /// again. An exchange dispatched with nothing owed owes nothing now: its statement is
    /// passed through, and nothing is produced, committed or numbered. An exchange whose
    /// intent was committed owes its outcome, and gets it committed or a refusal.
    pub(crate) async fn outcome(
        self,
        observed: AuditRecord,
    ) -> Result<OutcomeDisposition, Refusal> {
        match self {
            IntentDisposition::NotRequired(none) => Ok(OutcomeDisposition::NotRequired(none)),
            IntentDisposition::Committed(owed) => owed
                .commit(observed)
                .await
                .map(|committed| OutcomeDisposition::Committed(Box::new(committed))),
        }
    }
}

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

/// G2 for the exchange `coordinate` names, over `observed`.
async fn commit(
    provider: &Arc<EstablishedProvider>,
    bound: CommitmentBound,
    coordinate: ExchangeCoordinate,
    observed: AuditRecord,
) -> Result<CommittedOutcome, Refusal> {
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
fn cannot_commit() -> Refusal {
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
            commit(&provider, bound(50), coordinate(), observed(200)),
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
            let committed = commit(&provider, bound(200), c, observed(status))
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

    /// The outcome G1 leaves owed is committed for the exchange its intent named, to the
    /// provider the intent was committed to (D9): G2 is handed neither.
    #[tokio::test]
    async fn the_owed_outcome_is_committed_for_the_exchange_its_intent_named() {
        let (authority, provider) = provider([Step::Commit, Step::Commit]);
        let c = coordinate();
        let owed = super::super::intent::IntentCommitment::new(provider, bound(200))
            .commit(
                Some(c),
                crate::audit_record::ExecutionIntent::new("actor-a", 10),
            )
            .await
            .expect("the intent commits");
        let committed = owed
            .commit(observed(200))
            .await
            .expect("the outcome commits");
        assert_eq!(committed.envelope().scope(), EventScope::Exchange(c));
        let journaled = authority.journaled();
        assert_eq!(journaled.len(), 2);
        assert!(
            journaled.iter().all(|(_, named)| *named == Some(c)),
            "the intent and the outcome name one exchange"
        );
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
