// SPDX-License-Identifier: Apache-2.0
//! The established provider: the shared owner of the commit procedure, and the only scope
//! from which a [`CommitmentWitness`] can be minted.

/// Polling a provider under `catch_unwind`.
mod caught;
/// The witness, its single redemption, and the one function that mints it.
mod witness;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

use crate::audit_record::CanonicalEvent;

use super::accounting::CommitmentAccounting;
use super::{
    AuditPostureRefusal, CommitRequest, CommitmentAuthority, CommitmentBound, CommitmentFailure,
    Crossing, DurabilityTier, EstablishFailure, UncertainCause,
};
use caught::Caught;
pub(crate) use witness::{CommitmentWitness, Redeemed, WitnessRefusal};

/// A commitment authority that was ESTABLISHED: it declared a tier that meets the required
/// minimum, and its bounded startup probe answered `Ok` (ADR-MCPRE-070 D3, §11).
///
/// Holding one means both: [`EstablishedProvider::establish`] is the only production
/// constructor and refuses otherwise, so no caller re-checks the tier (R-SEAL). Whether the
/// provider actually persists anything is still its declaration and an external evidence
/// obligation — establishment proves the shared code's handling, not the store (D3).
///
/// Its identity is this value's `Arc` allocation: a witness binds the instance whose
/// `commit` minted it, and redeems only against that same instance. The identity is
/// process-local and unforgeable — nothing the provider says can name another instance.
pub(crate) struct EstablishedProvider {
    authority: Arc<dyn CommitmentAuthority>,
    tier: DurabilityTier,
    accounting: Arc<CommitmentAccounting>,
}

impl std::fmt::Debug for EstablishedProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstablishedProvider")
            .field("provider", self.accounting.provider())
            .field("tier", &self.tier)
            .finish_non_exhaustive()
    }
}

impl EstablishedProvider {
    /// Establish `authority` under `accounting`, waiting at most `bound` for its probe.
    ///
    /// The declared tier is read ONCE and refused below the minimum before the provider is
    /// asked anything; then the provider's own `establish` runs under the bound and
    /// `catch_unwind`. A failure, a timeout and a panic are each a refusal — and the refusal
    /// carries only the provider's name and a class, never its text.
    pub(crate) async fn establish(
        authority: Arc<dyn CommitmentAuthority>,
        accounting: Arc<CommitmentAccounting>,
        bound: Duration,
    ) -> Result<Arc<Self>, AuditPostureRefusal> {
        let provider = accounting.provider().clone();
        let tier = authority.declared_tier();
        if !tier.meets_required_minimum() {
            return Err(AuditPostureRefusal::TierBelowMinimum {
                provider,
                declared: tier,
            });
        }
        let failed = |class| AuditPostureRefusal::EstablishFailed {
            provider: provider.clone(),
            class,
        };
        let probe = catch_unwind(AssertUnwindSafe(|| authority.establish()))
            .map_err(|_| failed(EstablishFailure::Refused))?;
        tokio::time::timeout(bound, Caught::new(probe))
            .await
            .map_err(|_| AuditPostureRefusal::EstablishTimedOut {
                provider: provider.clone(),
                bound,
            })?
            .map_err(|_| failed(EstablishFailure::Refused))?
            .map_err(failed)?;
        Ok(Arc::new(EstablishedProvider {
            authority,
            tier,
            accounting,
        }))
    }

    /// An eligible authority, established without its probe. Unit tests of the commit
    /// procedure only; an ineligible tier still panics here.
    #[cfg(test)]
    pub(crate) fn eligible_for_test(authority: Arc<dyn CommitmentAuthority>) -> Arc<Self> {
        let tier = authority.declared_tier();
        assert!(
            tier.meets_required_minimum(),
            "an ineligible tier is never established"
        );
        let accounting =
            CommitmentAccounting::new(authority.provider_id(), super::budget::BUDGET_CEILING);
        Arc::new(EstablishedProvider {
            authority,
            tier,
            accounting: Arc::new(accounting),
        })
    }

    /// The tier the provider declared when it was established.
    pub(crate) fn tier(&self) -> DurabilityTier {
        self.tier
    }

    /// The provider's accounting and budget.
    pub(crate) fn accounting(&self) -> &CommitmentAccounting {
        &self.accounting
    }

    /// Commit `envelope` at crossing `K`, waiting at most `bound`. The ONE way to obtain a
    /// witness.
    ///
    /// A permit of the commitment budget is TRIED first: a spent budget is `Unavailable` at
    /// once, and the provider is not asked (§7.3, §7.4). The permit and the provider's future
    /// run inside this future: nothing is spawned or detached, and no thread is blocked.
    /// Dropping this future drops both, and that is the cancellation that returns nothing —
    /// safe, because whatever the witness would have authorized lives in the same dropped
    /// future, and counted as uncertain. Every answer that DOES return is typed: a provider
    /// failure, a timeout, a panic, or a receipt that does not match what was sent all become
    /// [`CommitmentFailure`], and none of them is absorbed.
    pub(crate) async fn commit<K: Crossing>(
        self: &Arc<Self>,
        envelope: &CanonicalEvent,
        bound: CommitmentBound,
    ) -> Result<CommitmentWitness<K>, CommitmentFailure> {
        let Some(_permit) = self.accounting.budget().try_acquire() else {
            self.accounting.note_budget_exhausted();
            return Err(CommitmentFailure::Unavailable);
        };
        let attempt = self.accounting.attempt();
        let answer = self.ask::<K>(envelope, bound).await;
        attempt.settle(&answer);
        answer
    }

    /// One bounded, caught request to the provider, and the check of its receipt.
    async fn ask<K: Crossing>(
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
    use crate::audit_commitment::reference::{EstablishStep, ReferenceAuthority, Step};
    use crate::audit_commitment::{Intent, RejectReason};

    const ELIGIBLE: DurabilityTier = DurabilityTier::SurvivesProxyProcessLoss;

    async fn commit_one(step: Step, bound: Duration) -> Result<(), CommitmentFailure> {
        let authority = Arc::new(ReferenceAuthority::new(ELIGIBLE).scripted([step]));
        let provider = EstablishedProvider::eligible_for_test(authority);
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

    fn accounting_for(authority: &ReferenceAuthority) -> Arc<CommitmentAccounting> {
        Arc::new(CommitmentAccounting::new(authority.provider_id(), 4))
    }

    async fn establish(authority: ReferenceAuthority, bound: Duration) -> Result<(), String> {
        let authority = Arc::new(authority);
        let accounting = accounting_for(&authority);
        tokio::time::timeout(
            Duration::from_secs(5),
            EstablishedProvider::establish(authority, accounting, bound),
        )
        .await
        .expect("the establishment bound fired before the outer bound")
        .map(|_| ())
        .map_err(|refusal| refusal.to_string())
    }

    /// The tier is read once, and an eligible provider whose probe answers is established.
    #[tokio::test]
    async fn an_eligible_provider_that_answers_is_established_reading_its_tier_once() {
        let authority = Arc::new(ReferenceAuthority::new(ELIGIBLE));
        let accounting = accounting_for(&authority);
        let established =
            EstablishedProvider::establish(authority.clone(), accounting, Duration::from_secs(1))
                .await
                .expect("established");
        assert_eq!(established.tier(), ELIGIBLE);
        assert_eq!(authority.tier_reads(), 1);
    }

    /// D3: a volatile tier is refused before the provider is asked anything.
    #[tokio::test]
    async fn a_tier_below_the_minimum_is_refused_before_the_probe() {
        let refused = establish(
            ReferenceAuthority::new(DurabilityTier::ProcessVolatile),
            Duration::from_secs(1),
        )
        .await
        .expect_err("refused");
        assert!(refused.contains("PROCESS_VOLATILE"), "{refused}");
    }

    /// A probe that fails, hangs or panics refuses startup, each with its class.
    #[tokio::test]
    async fn a_probe_that_fails_hangs_or_panics_is_refused() {
        for (script, expected) in [
            (
                EstablishStep::Fail(EstablishFailure::Unreachable),
                "UNREACHABLE",
            ),
            (EstablishStep::Hang, "not established within 20ms"),
            (EstablishStep::PanicInPoll, "REFUSED"),
            (EstablishStep::PanicBeforeFuture, "REFUSED"),
        ] {
            let authority = ReferenceAuthority::new(ELIGIBLE).establishing(script);
            let refused = establish(authority, Duration::from_millis(20))
                .await
                .expect_err("refused");
            assert!(refused.contains(expected), "{refused}");
        }
    }

    /// A provider's own error text never reaches the refusal: only its name and a class.
    #[tokio::test]
    async fn the_refusal_carries_no_provider_text() {
        let authority = ReferenceAuthority::new(ELIGIBLE)
            .establishing(EstablishStep::FailSaying("redis://user:SECRET-xyz@host"));
        let refused = establish(authority, Duration::from_secs(1))
            .await
            .expect_err("refused");
        assert!(!refused.contains("SECRET"), "{refused}");
        assert!(refused.contains("provider reference"), "{refused}");
    }

    /// A spent budget is `Unavailable` at once, the provider is not asked, and the refusal
    /// is counted as such (§7.3).
    #[tokio::test]
    async fn a_spent_budget_refuses_before_the_provider_is_asked() {
        let authority = Arc::new(ReferenceAuthority::new(ELIGIBLE).scripted([Step::Hang]));
        let accounting = Arc::new(CommitmentAccounting::new(authority.provider_id(), 1));
        let provider =
            EstablishedProvider::establish(authority.clone(), accounting, Duration::from_secs(1))
                .await
                .expect("established");
        let envelope = fixtures::envelope(0, "actor-a");
        let bound = CommitmentBound::new(Duration::from_secs(1)).expect("legal bound");
        let holding = provider.commit::<Intent>(&envelope, bound);
        tokio::pin!(holding);
        assert!(futures_poll_once(holding.as_mut()).await);
        let refused = provider.commit::<Intent>(&envelope, bound).await;
        assert_eq!(refused.map(|_| ()), Err(CommitmentFailure::Unavailable));
        assert_eq!(
            authority.requests(),
            1,
            "the second commitment asked nobody"
        );
        assert_eq!(provider.accounting().snapshot().budget_exhausted, 1);
        assert_eq!(provider.accounting().budget().outstanding(), 1);
    }

    /// Poll `f` once; `true` when it is still pending.
    async fn futures_poll_once<F: std::future::Future>(f: std::pin::Pin<&mut F>) -> bool {
        let mut f = Some(f);
        std::future::poll_fn(move |cx| {
            let pending = f.as_mut().map(|f| f.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(pending.unwrap_or(false))
        })
        .await
    }

    /// The commit future can be awaited inside a `Send` request future.
    #[test]
    fn the_commit_future_is_send() {
        fn send<T: Send>(_: &T) {}
        let provider =
            EstablishedProvider::eligible_for_test(Arc::new(ReferenceAuthority::new(ELIGIBLE)));
        let envelope = fixtures::envelope(0, "actor-a");
        let bound = CommitmentBound::new(Duration::from_secs(1)).expect("legal bound");
        send(&provider.commit::<Intent>(&envelope, bound));
    }
}
