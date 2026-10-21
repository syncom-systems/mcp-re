// SPDX-License-Identifier: Apache-2.0
//! The established provider: the shared owner of the commit procedure, and the only scope
//! from which a [`CommitmentWitness`] can be minted.

/// Polling a provider under `catch_unwind`.
mod caught;
/// The witness, its single redemption, and the one function that mints it.
mod witness;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use crate::audit_record::CanonicalEvent;

use super::{
    CommitRequest, CommitmentAuthority, CommitmentBound, CommitmentFailure, Crossing,
    DurabilityTier, UncertainCause,
};
use caught::Caught;
pub(crate) use witness::{CommitmentWitness, Redeemed, WitnessRefusal};

/// A commitment authority together with the tier it declared when it was established.
///
/// Its identity is this value's `Arc` allocation: a witness binds the instance whose
/// `commit` minted it, and redeems only against that same instance. The identity is
/// process-local and unforgeable — nothing the provider says can name another instance.
pub(crate) struct EstablishedProvider {
    authority: Arc<dyn CommitmentAuthority>,
    tier: DurabilityTier,
}

impl std::fmt::Debug for EstablishedProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstablishedProvider")
            .field("tier", &self.tier)
            .finish_non_exhaustive()
    }
}

impl EstablishedProvider {
    /// Establish `authority`, reading its declared tier once.
    #[cfg_attr(
        not(any(test, feature = "audit_commitment_reference")),
        allow(dead_code)
    )] // only the test-only installer establishes an authority until #1206
    pub(crate) fn establish(authority: Arc<dyn CommitmentAuthority>) -> Arc<Self> {
        let tier = authority.declared_tier();
        Arc::new(EstablishedProvider { authority, tier })
    }

    /// Whether this provider's declared tier may serve the required posture (D3).
    #[cfg_attr(
        not(any(test, feature = "audit_commitment_reference")),
        allow(dead_code)
    )] // read by the test-only installer's refusal until #1206's startup refusal
    pub(crate) fn meets_required_minimum(&self) -> bool {
        self.tier.meets_required_minimum()
    }

    /// Commit `envelope` at crossing `K`, waiting at most `bound`. The ONE way to obtain a
    /// witness.
    ///
    /// The provider's future runs inside this future: nothing is spawned or detached, and
    /// no thread is blocked. Dropping this future drops the provider's, and that is the
    /// cancellation that returns nothing — safe, because whatever the witness would have
    /// authorized lives in the same dropped future. Every answer that DOES return is typed:
    /// a provider failure, a timeout, a panic, or a receipt that does not match what was
    /// sent all become [`CommitmentFailure`], and none of them is absorbed.
    pub(crate) async fn commit<K: Crossing>(
        self: &Arc<Self>,
        envelope: &CanonicalEvent,
        bound: CommitmentBound,
    ) -> Result<CommitmentWitness<K>, CommitmentFailure> {
        let request = CommitRequest::new(envelope, K::KIND, self.tier);
        let pending = catch_unwind(AssertUnwindSafe(|| self.authority.commit(request)))
            .map_err(|_| CommitmentFailure::Uncertain(UncertainCause::ProviderPanicked))?;
        let answer = tokio::time::timeout(bound.get(), Caught::new(pending))
            .await
            .map_err(|_| CommitmentFailure::Uncertain(UncertainCause::TimedOut))?
            .map_err(|_| CommitmentFailure::Uncertain(UncertainCause::ProviderPanicked))?;
        let receipt = answer.map_err(CommitmentFailure::from_provider)?;
        witness::mint(self, envelope, receipt)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::audit_commitment::fixtures;
    use crate::audit_commitment::reference::{ReferenceAuthority, Step};
    use crate::audit_commitment::{Intent, RejectReason};

    const ELIGIBLE: DurabilityTier = DurabilityTier::SurvivesProxyProcessLoss;

    async fn commit_one(step: Step, bound: Duration) -> Result<(), CommitmentFailure> {
        let authority = Arc::new(ReferenceAuthority::new(ELIGIBLE).scripted([step]));
        let provider = EstablishedProvider::establish(authority);
        let bound = CommitmentBound::new(bound).expect("legal bound");
        let outer = Duration::from_secs(5);
        tokio::time::timeout(
            outer,
            provider.commit::<Intent>(&fixtures::envelope(0, "actor-a"), bound),
        )
        .await
        .expect("the commitment bound fired before the outer bound")
        .map(|_witness| ())
    }

    #[tokio::test]
    async fn a_committed_event_yields_a_witness() {
        assert_eq!(
            commit_one(Step::Commit, Duration::from_secs(1)).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn a_provider_rejection_is_typed_rejected() {
        assert_eq!(
            commit_one(Step::Reject(RejectReason::Refused), Duration::from_secs(1)).await,
            Err(CommitmentFailure::Rejected(RejectReason::Refused))
        );
    }

    #[tokio::test]
    async fn an_unavailable_provider_is_typed_unavailable() {
        assert_eq!(
            commit_one(Step::Unavailable, Duration::from_secs(1)).await,
            Err(CommitmentFailure::Unavailable)
        );
    }

    #[tokio::test]
    async fn a_provider_that_never_answers_is_uncertain_timed_out_within_the_bound() {
        assert_eq!(
            commit_one(Step::Hang, Duration::from_millis(10)).await,
            Err(CommitmentFailure::Uncertain(UncertainCause::TimedOut))
        );
    }

    #[tokio::test]
    async fn a_dropped_provider_completion_is_uncertain_cancelled() {
        assert_eq!(
            commit_one(Step::DropCompletion, Duration::from_secs(1)).await,
            Err(CommitmentFailure::Uncertain(UncertainCause::Cancelled))
        );
    }

    #[tokio::test]
    async fn a_provider_panic_while_polled_is_uncertain_and_does_not_unwind() {
        assert_eq!(
            commit_one(Step::PanicInPoll, Duration::from_secs(1)).await,
            Err(CommitmentFailure::Uncertain(
                UncertainCause::ProviderPanicked
            ))
        );
    }

    #[tokio::test]
    async fn a_provider_panic_before_its_future_exists_is_uncertain_and_does_not_unwind() {
        assert_eq!(
            commit_one(Step::PanicBeforeFuture, Duration::from_secs(1)).await,
            Err(CommitmentFailure::Uncertain(
                UncertainCause::ProviderPanicked
            ))
        );
    }

    #[test]
    fn the_tier_is_read_once_at_establishment() {
        let authority = Arc::new(ReferenceAuthority::new(ELIGIBLE));
        let provider = EstablishedProvider::establish(authority.clone());
        assert!(provider.meets_required_minimum());
        assert!(provider.meets_required_minimum());
        assert_eq!(authority.tier_reads(), 1);
    }

    #[test]
    fn an_ineligible_tier_is_reported_by_meets_required_minimum() {
        let provider = EstablishedProvider::establish(Arc::new(ReferenceAuthority::new(
            DurabilityTier::ProcessVolatile,
        )));
        assert!(!provider.meets_required_minimum());
    }

    /// The commit future can be awaited inside a `Send` request future.
    #[test]
    fn the_commit_future_is_send() {
        fn send<T: Send>(_: &T) {}
        let provider = EstablishedProvider::establish(Arc::new(ReferenceAuthority::new(ELIGIBLE)));
        let envelope = fixtures::envelope(0, "actor-a");
        let bound = CommitmentBound::new(Duration::from_secs(1)).expect("legal bound");
        send(&provider.commit::<Intent>(&envelope, bound));
    }
}
