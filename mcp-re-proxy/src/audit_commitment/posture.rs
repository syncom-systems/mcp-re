// SPDX-License-Identifier: Apache-2.0
//! How a deployment delivers its audit facts (ADR-MCPRE-070 §2).
//!
//! Two mechanisms, one decision. The OBSERVER is offered every record and can authorize
//! nothing; the COMMITMENT, when the posture requires one, is a prerequisite of dispatch.
//! They are held by one owner because they are one operator choice with a compatibility rule
//! between them (a required posture refuses `--audit-sink none`, #1206) — not because they
//! are one authority: the observer still mints nothing, and each is projected separately.
//!
//! # Reachability before #1206
//!
//! The required posture is entered only through [`AuditPosture::require`], which exists only
//! in test builds and under the test-only `audit_commitment_reference` feature. The default
//! library cannot hold one: every deployable build serves the best-effort posture until the
//! operator selector lands.

use std::time::Duration;

use crate::audit_record::{ExchangeCoordinate, ExecutionIntent};
use crate::audit_sink::MaybeAuditSink;
use crate::refusal::Refusal;
use crate::request_stages::IntentDisposition;

use super::intent::IntentCommitment;
use super::NoCommitmentRequired;

/// The deployment's audit posture: the observer it offers records to, and whether an
/// execution intent must be committed before dispatch.
pub(crate) struct AuditPosture {
    /// The ADR-MCPS-035 observer. `None` is the explicit no-emission posture; an observer's
    /// failure never fails a request.
    observer: MaybeAuditSink,
    commitment: Commitment,
}

/// Whether a durable commitment is a prerequisite of dispatch.
enum Commitment {
    /// Best-effort observation only (v0.18.1 behavior).
    BestEffort,
    /// Every dispatch requires the exchange's committed intent (G1).
    #[cfg_attr(
        not(any(test, feature = "audit_commitment_reference")),
        allow(dead_code)
    )] // entered only through the test-only `require` until #1206 selects the posture
    Required(IntentCommitment),
}

impl AuditPosture {
    /// The best-effort posture over `observer`.
    pub(crate) fn best_effort(observer: MaybeAuditSink) -> Self {
        AuditPosture {
            observer,
            commitment: Commitment::BestEffort,
        }
    }

    /// The observer every record is offered to.
    pub(crate) fn observer(&self) -> &MaybeAuditSink {
        &self.observer
    }

    /// Offer every record to `observer` from now on. The commitment posture is unchanged.
    pub(crate) fn observe_with(&mut self, observer: MaybeAuditSink) {
        self.observer = observer;
    }

    /// The longest the intent crossing can hold an exchange before dispatch: zero under the
    /// best-effort posture. A signing window must survive this wait as well as the dispatch.
    pub(crate) fn pre_dispatch_wait(&self) -> Duration {
        match &self.commitment {
            Commitment::BestEffort => Duration::ZERO,
            Commitment::Required(crossing) => crossing.wait(),
        }
    }

    /// G1: what this exchange holds at the intent crossing.
    ///
    /// Under the best-effort posture the owner states that nothing was owed, and nothing is
    /// produced, committed or numbered. Under the required posture the exchange's intent is
    /// committed and its witness redeemed, or the crossing refuses — before the backend is
    /// reached, so every refusal here is free of execution.
    pub(crate) async fn intent(
        &self,
        coordinate: Option<ExchangeCoordinate>,
        intent: ExecutionIntent<'_>,
    ) -> Result<IntentDisposition, Refusal> {
        match &self.commitment {
            Commitment::BestEffort => Ok(IntentDisposition::NotRequired(
                NoCommitmentRequired::minted_by_posture(),
            )),
            Commitment::Required(crossing) => crossing
                .commit(coordinate, intent)
                .await
                .map(IntentDisposition::Committed),
        }
    }

    /// Require a committed intent before every dispatch, committed to `authority` within
    /// `bound`. Test builds and the test-only `audit_commitment_reference` feature only.
    ///
    /// Refuses an authority whose declared tier cannot serve the required posture (D3) and a
    /// bound that is zero or above the request deadline, so not even a test runs the required
    /// posture over a volatile store or a wait that outlasts the request it gates.
    #[cfg(any(test, feature = "audit_commitment_reference"))]
    pub(crate) fn require(
        &mut self,
        authority: std::sync::Arc<dyn super::CommitmentAuthority>,
        bound: Duration,
    ) -> Result<(), &'static str> {
        let bound = super::CommitmentBound::new(bound)
            .ok_or("the commitment bound is zero or above the request deadline")?;
        let crossing =
            IntentCommitment::over(super::EstablishedProvider::establish(authority), bound)
                .ok_or("the authority's declared tier cannot serve the required posture (D3)")?;
        self.commitment = Commitment::Required(crossing);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::audit_commitment::reference::{ReferenceAuthority, Step};
    use crate::audit_commitment::DurabilityTier;

    fn eligible(steps: impl IntoIterator<Item = Step>) -> Arc<ReferenceAuthority> {
        Arc::new(ReferenceAuthority::new(DurabilityTier::SurvivesProxyProcessLoss).scripted(steps))
    }

    fn required(authority: &Arc<ReferenceAuthority>, bound: Duration) -> AuditPosture {
        let mut posture = AuditPosture::best_effort(None);
        posture.require(authority.clone(), bound).expect("eligible");
        posture
    }

    /// Best-effort mints the owner's statement and asks no provider anything: no intent is
    /// produced, numbered or committed, so the observed stream is unchanged (D1).
    #[tokio::test]
    async fn only_best_effort_mints_not_required() {
        let posture = AuditPosture::best_effort(None);
        assert_eq!(posture.pre_dispatch_wait(), Duration::ZERO);
        let disposition = posture
            .intent(None, ExecutionIntent::new("actor-a", 1))
            .await
            .expect("best-effort never refuses");
        assert!(matches!(disposition, IntentDisposition::NotRequired(_)));
    }

    /// Under the required posture the crossing yields a committed intent or a refusal —
    /// never the best-effort statement, whatever the provider answers.
    #[tokio::test]
    async fn the_required_posture_never_yields_not_required() {
        let committing = eligible([Step::Commit]);
        let posture = required(&committing, Duration::from_millis(200));
        assert_eq!(posture.pre_dispatch_wait(), Duration::from_millis(200));
        let coordinate = crate::audit_record::record_to(
            &None,
            None,
            crate::audit_record::AuditSubject::request_accepted(
                &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                crate::admission_enforcer::AdmissionFacet::NotConfigured,
            ),
            None,
            200,
            1,
        );
        let committed = posture
            .intent(coordinate, ExecutionIntent::new("actor-a", 1))
            .await
            .expect("committed");
        assert!(matches!(committed, IntentDisposition::Committed(_)));
        assert_eq!(committing.requests(), 1);

        let refusing = required(&eligible([Step::Unavailable]), Duration::from_millis(200));
        assert!(refusing
            .intent(coordinate, ExecutionIntent::new("actor-a", 1))
            .await
            .is_err());
        assert!(
            required(&eligible([]), Duration::from_millis(200))
                .intent(None, ExecutionIntent::new("actor-a", 1))
                .await
                .is_err(),
            "no coordinate, no intent, no dispatch"
        );
    }

    /// D3 and the bound: the required posture is refused over a volatile authority and over
    /// a wait the request could not survive, and the posture is left as it was.
    #[test]
    fn the_required_posture_is_refused_over_a_volatile_authority_or_an_illegal_bound() {
        let mut posture = AuditPosture::best_effort(None);
        let volatile = Arc::new(ReferenceAuthority::new(DurabilityTier::ProcessVolatile));
        assert!(posture.require(volatile, Duration::from_secs(1)).is_err());
        assert!(posture.require(eligible([]), Duration::ZERO).is_err());
        assert!(posture
            .require(eligible([]), Duration::from_secs(3600))
            .is_err());
        assert_eq!(
            posture.pre_dispatch_wait(),
            Duration::ZERO,
            "still best-effort"
        );
    }

    /// The observer is the posture's other mechanism, and installing one changes nothing
    /// about the commitment.
    #[test]
    fn installing_an_observer_keeps_the_commitment_posture() {
        let mut posture = required(&eligible([]), Duration::from_millis(5));
        let sink: Arc<dyn crate::audit_sink::AuditSink> =
            Arc::new(crate::audit_sink::CollectingAuditSink::new());
        posture.observe_with(Some(sink));
        assert!(posture.observer().is_some());
        assert_eq!(posture.pre_dispatch_wait(), Duration::from_millis(5));
    }
}
