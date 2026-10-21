// SPDX-License-Identifier: Apache-2.0
//! The deterministic reference commitment authority. Test-only: this module is declared
//! `#[cfg(any(test, feature = "audit_commitment_reference"))]`, and that feature is
//! registered test-only (`scripts/fixture_feature_gate.py`), so no deployable build contains
//! it and no deployment can select it (ADR-MCPRE-070 §9, §14 item 10).
//!
//! It exercises the shared owner's machine. It persists nothing, keeps no clock, draws no
//! randomness and spawns nothing: each answer is the next scripted [`Step`]. Like any
//! provider it answers with receipts or failures only — it cannot name the function that
//! mints a witness, so even a forged receipt goes through the owner's checks.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::audit_record::{ContentDigest, EventBinding, EventId, ExchangeCoordinate};

use super::forgery::forged;
pub(crate) use super::forgery::Forgery;
pub(crate) use super::reference_probe::EstablishStep;
pub(crate) use super::reference_step::{Hook, Step};
use super::{
    CommitFuture, CommitRequest, CommitmentAuthority, CommitmentReceipt, CrossingKind,
    DurabilityTier, EstablishFuture, ProviderFailure, ProviderId, RejectReason,
};

/// A scripted, in-memory authority.
#[derive(Debug)]
pub(crate) struct ReferenceAuthority {
    tier: DurabilityTier,
    establishing: EstablishStep,
    script: Mutex<VecDeque<Step>>,
    journal: Mutex<HashMap<EventId, ContentDigest>>,
    /// Every event journaled, in order, with the exchange it names.
    journaled: Mutex<Vec<(EventId, Option<ExchangeCoordinate>)>>,
    previous: Mutex<Option<(EventBinding, CrossingKind)>>,
    tier_reads: AtomicUsize,
    requests: AtomicUsize,
}

impl ReferenceAuthority {
    /// An authority declaring `tier`, whose every answer is a commit.
    pub(crate) fn new(tier: DurabilityTier) -> Self {
        ReferenceAuthority {
            tier,
            establishing: EstablishStep::Succeed,
            script: Mutex::new(VecDeque::new()),
            journal: Mutex::new(HashMap::new()),
            journaled: Mutex::new(Vec::new()),
            previous: Mutex::new(None),
            tier_reads: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
        }
    }

    /// This authority, answering `steps` in order.
    pub(crate) fn scripted(self, steps: impl IntoIterator<Item = Step>) -> Self {
        self.script.lock().expect("script").extend(steps);
        self
    }

    /// This authority, answering its startup probe with `step`. Unit tests only: the
    /// serving suites drive establishment failures with a provider of their own, through the
    /// public seam.
    #[cfg(test)]
    pub(crate) fn establishing(self, step: EstablishStep) -> Self {
        ReferenceAuthority {
            establishing: step,
            ..self
        }
    }

    /// How many times the tier was asked for.
    #[cfg(test)]
    pub(crate) fn tier_reads(&self) -> usize {
        self.tier_reads.load(Ordering::SeqCst)
    }

    /// How many commits this authority was asked for, whatever it answered.
    pub(crate) fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// Every event journaled, in order: its identity, and the exchange it names.
    pub(crate) fn journaled(&self) -> Vec<(EventId, Option<ExchangeCoordinate>)> {
        self.journaled.lock().expect("journaled").clone()
    }

    fn journal(&self, request: &CommitRequest<'_>) -> Result<CommitmentReceipt, ProviderFailure> {
        let binding = request.binding();
        let mut journal = self.journal.lock().expect("journal");
        let recorded = *journal.entry(binding.id()).or_insert(binding.digest());
        if recorded != binding.digest() {
            return Err(ProviderFailure::Rejected(RejectReason::IdentityConflict));
        }
        self.journaled
            .lock()
            .expect("journaled")
            .push((binding.id(), request.exchange_coordinate()));
        *self.previous.lock().expect("previous") = Some((binding, request.crossing()));
        Ok(CommitmentReceipt::new(
            binding,
            request.crossing(),
            request.tier(),
        ))
    }

    fn answer(&self, step: Step, request: &CommitRequest<'_>) -> CommitFuture<'static> {
        let answer = match step {
            Step::Commit => self.journal(request),
            Step::Reject(reason) => Err(ProviderFailure::Rejected(reason)),
            Step::Unavailable => Err(ProviderFailure::Unavailable),
            Step::Hang => return Box::pin(std::future::pending()),
            Step::DropCompletion => {
                let (acknowledge, acknowledged) = tokio::sync::oneshot::channel::<()>();
                drop(acknowledge);
                return Box::pin(async move {
                    acknowledged.await.map_err(|_| ProviderFailure::Cancelled)?;
                    Err(ProviderFailure::Unavailable)
                });
            }
            Step::PanicInPoll => return Box::pin(async { panic!("reference provider fault") }),
            Step::PanicBeforeFuture => panic!("reference provider fault before its future"),
            Step::Forge(forgery) => Ok(forged(forgery, request)),
            Step::CommitThenPark => {
                let _ = self.journal(request);
                return Box::pin(std::future::pending());
            }
            Step::CommitThen(Hook(hook)) => {
                let receipt = self.journal(request);
                hook();
                receipt
            }
            Step::ReplayPrevious => {
                let (binding, crossing) = self
                    .previous
                    .lock()
                    .expect("previous")
                    .expect("a previous commit to replay");
                Ok(CommitmentReceipt::new(binding, crossing, request.tier()))
            }
        };
        Box::pin(std::future::ready(answer))
    }
}

impl CommitmentAuthority for ReferenceAuthority {
    fn provider_id(&self) -> ProviderId {
        ProviderId::reference()
    }

    fn establish(&self) -> EstablishFuture<'_> {
        self.establishing.clone().answer()
    }

    fn declared_tier(&self) -> DurabilityTier {
        self.tier_reads.fetch_add(1, Ordering::SeqCst);
        self.tier
    }

    fn commit<'a>(&'a self, request: CommitRequest<'a>) -> CommitFuture<'a> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let step = self
            .script
            .lock()
            .expect("script")
            .pop_front()
            .unwrap_or(Step::Commit);
        self.answer(step, &request)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::audit_commitment::fixtures;
    use crate::audit_commitment::{
        CommitmentBound, CommitmentFailure, EstablishedProvider, Intent,
    };

    fn bound() -> CommitmentBound {
        CommitmentBound::new(Duration::from_secs(1)).expect("legal bound")
    }

    #[tokio::test]
    async fn an_identical_retry_is_deduplicated_to_an_equal_receipt() {
        let authority = ReferenceAuthority::new(DurabilityTier::ProcessVolatile);
        let envelope = fixtures::envelope(0, "actor-a");
        let request = CommitRequest::new(&envelope, CrossingKind::Intent, authority.tier);
        let first = authority.commit(request).await;
        let retried = authority.commit(request).await;
        assert!(first.is_ok());
        assert_eq!(first, retried);
    }

    #[tokio::test]
    async fn the_same_id_with_other_bytes_is_an_identity_conflict() {
        let provider = EstablishedProvider::eligible_for_test(Arc::new(ReferenceAuthority::new(
            DurabilityTier::SurvivesProxyProcessLoss,
        )));
        let (first, conflicting) = fixtures::same_id_other_content();
        assert!(provider.commit::<Intent>(&first, bound()).await.is_ok());
        assert_eq!(
            provider
                .commit::<Intent>(&conflicting, bound())
                .await
                .map(|_| ()),
            Err(CommitmentFailure::Rejected(RejectReason::IdentityConflict))
        );
    }

    #[tokio::test]
    async fn the_same_script_yields_the_same_outcomes() {
        let script = [
            Step::Commit,
            Step::Reject(RejectReason::Refused),
            Step::Unavailable,
            Step::DropCompletion,
            Step::Forge(Forgery::Tier),
            Step::ReplayPrevious,
        ];
        let run = || async {
            let provider = EstablishedProvider::eligible_for_test(Arc::new(
                ReferenceAuthority::new(DurabilityTier::SurvivesProxyProcessLoss)
                    .scripted(script.clone()),
            ));
            let mut outcomes = Vec::new();
            for seq in 0..6 {
                let envelope = fixtures::envelope(seq, "actor-a");
                let outcome = provider.commit::<Intent>(&envelope, bound()).await;
                outcomes.push(outcome.map(|_| ()));
            }
            outcomes
        };
        let first = run().await;
        assert_eq!(first, run().await);
        assert_eq!(first.first(), Some(&Ok(())));
    }
}
