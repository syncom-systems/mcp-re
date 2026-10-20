// SPDX-License-Identifier: Apache-2.0
//! The commitment witness: minted by the shared owner from a checked receipt, and redeemed
//! once at the crossing it gates (ADR-MCPRE-070 §9, P4).
//!
//! The witness, its redemption and its proof of redemption share this file because privacy
//! is the seal: the witness's fields are readable only here, so [`mint`] is the only literal
//! construction of a witness and [`CommitmentWitness::redeem`] the only one of a
//! [`Redeemed`]. `mint` is visible to `established` alone, so the reference authority, the
//! observer and the serving path cannot name it.

use std::marker::PhantomData;
use std::sync::Arc;

use crate::audit_record::{AuditEnvelope, EventBinding};

use super::super::{
    BindingField, CommitmentFailure, CommitmentReceipt, Crossing, DurabilityTier, UncertainCause,
};
use super::EstablishedProvider;

/// Evidence that one established provider acknowledged one event at crossing `K`, at the
/// tier it declared.
///
/// Bound to the event's identity and digest, to the provider INSTANCE that was called, and
/// (by type) to the crossing. Not `Clone`, `Copy`, `Default` or serializable: it is spent by
/// [`CommitmentWitness::redeem`], once. It says nothing about whether the provider really
/// persisted the event — that is the provider's assumption to evidence, not this type's.
#[must_use = "a commitment witness is evidence only when redeemed at its crossing"]
#[derive(Debug)]
pub(crate) struct CommitmentWitness<K: Crossing> {
    binding: EventBinding,
    provider: Arc<EstablishedProvider>,
    _crossing: PhantomData<fn() -> K>,
}

/// Why a witness was refused at its crossing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WitnessRefusal {
    /// It witnesses another event — including the same position in another run.
    AnotherEvent,
    /// It witnesses this identity with other content.
    OtherContent,
    /// It was minted by another established provider than the one the crossing holds now.
    StaleProvider,
}

/// Proof that a witness was redeemed for THIS exchange's event against THIS provider at
/// crossing `K`. Produced only by [`CommitmentWitness::redeem`].
#[derive(Debug)]
pub(crate) struct Redeemed<K: Crossing> {
    binding: EventBinding,
    tier: DurabilityTier,
    _crossing: PhantomData<fn() -> K>,
}

/// Check `receipt` against what was sent at crossing `K` to `provider`, and only then mint.
///
/// A receipt that names another binding, the other crossing, or another tier than the
/// provider declared is not this commitment, so it is `Uncertain`: the provider said `Ok`
/// to something, and what it committed cannot be known from a receipt that disagrees.
pub(super) fn mint<K: Crossing>(
    provider: &Arc<EstablishedProvider>,
    sent: &AuditEnvelope,
    receipt: CommitmentReceipt,
) -> Result<CommitmentWitness<K>, CommitmentFailure> {
    let mismatch = |field| CommitmentFailure::Uncertain(UncertainCause::ReceiptMismatch(field));
    let binding = sent.binding();
    if receipt.binding() != binding {
        return Err(mismatch(binding_field(receipt.binding(), binding)));
    }
    if receipt.crossing() != K::KIND {
        return Err(mismatch(BindingField::Crossing));
    }
    if receipt.tier() != provider.tier {
        return Err(mismatch(BindingField::Tier));
    }
    Ok(CommitmentWitness {
        binding,
        provider: Arc::clone(provider),
        _crossing: PhantomData,
    })
}

/// Which half of two unequal bindings differs. The digest is over bytes that encode the
/// identity, so another event differs in both; the identity is named first because it is
/// the more specific diagnosis.
fn binding_field(got: EventBinding, expected: EventBinding) -> BindingField {
    if got.id() != expected.id() {
        BindingField::EventId
    } else {
        BindingField::Digest
    }
}

impl<K: Crossing> CommitmentWitness<K> {
    /// Spend this witness at its crossing for `expected`, the event the crossing is about,
    /// against `current`, the provider the crossing holds now.
    #[cfg_attr(not(test), allow(dead_code))] // no production crossing redeems yet
    pub(crate) fn redeem(
        self,
        expected: &AuditEnvelope,
        current: &Arc<EstablishedProvider>,
    ) -> Result<Redeemed<K>, WitnessRefusal> {
        let binding = expected.binding();
        if self.binding != binding {
            return Err(match binding_field(self.binding, binding) {
                BindingField::EventId => WitnessRefusal::AnotherEvent,
                _ => WitnessRefusal::OtherContent,
            });
        }
        if !Arc::ptr_eq(&self.provider, current) {
            return Err(WitnessRefusal::StaleProvider);
        }
        Ok(Redeemed {
            binding,
            tier: current.tier,
            _crossing: PhantomData,
        })
    }
}

impl<K: Crossing> Redeemed<K> {
    /// The event that was committed.
    #[cfg_attr(not(test), allow(dead_code))] // read by the crossing's disposition; none is wired yet
    pub(crate) fn binding(&self) -> EventBinding {
        self.binding
    }

    /// The tier it was committed at.
    #[cfg_attr(not(test), allow(dead_code))] // read by the crossing's disposition; none is wired yet
    pub(crate) fn tier(&self) -> DurabilityTier {
        self.tier
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::audit_commitment::fixtures;
    use crate::audit_commitment::reference::{Forgery, ReferenceAuthority, Step};
    use crate::audit_commitment::{CommitmentBound, Intent, Outcome};

    const TIER: DurabilityTier = DurabilityTier::SurvivesProxyProcessLoss;

    fn bound() -> CommitmentBound {
        CommitmentBound::new(Duration::from_secs(1)).expect("legal bound")
    }

    fn provider(steps: impl IntoIterator<Item = Step>) -> Arc<EstablishedProvider> {
        EstablishedProvider::establish(Arc::new(ReferenceAuthority::new(TIER).scripted(steps)))
    }

    fn mismatch(field: BindingField) -> Result<(), CommitmentFailure> {
        Err(CommitmentFailure::Uncertain(
            UncertainCause::ReceiptMismatch(field),
        ))
    }

    async fn minted(
        provider: &Arc<EstablishedProvider>,
        sent: &AuditEnvelope,
    ) -> Result<(), CommitmentFailure> {
        provider.commit::<Intent>(sent, bound()).await.map(|_| ())
    }

    #[tokio::test]
    async fn a_receipt_matching_the_sent_envelope_mints_a_witness() {
        let sent = fixtures::envelope(0, "actor-a");
        let provider = provider([Step::Commit]);
        let witness = provider
            .commit::<Intent>(&sent, bound())
            .await
            .expect("minted");
        let redeemed = witness.redeem(&sent, &provider).expect("redeemed");
        assert_eq!(redeemed.binding(), sent.binding());
        assert_eq!(redeemed.tier(), TIER);
    }

    #[tokio::test]
    async fn a_receipt_for_another_event_is_refused() {
        let donor = fixtures::envelope(9, "actor-b").binding();
        let provider = provider([Step::Forge(Forgery::Binding(donor))]);
        let sent = fixtures::envelope(0, "actor-a");
        assert_eq!(
            minted(&provider, &sent).await,
            mismatch(BindingField::EventId)
        );
    }

    #[tokio::test]
    async fn a_receipt_for_other_bytes_is_refused() {
        let (sent, same_id_other_bytes) = fixtures::same_id_other_content();
        let provider = provider([Step::Forge(Forgery::Binding(same_id_other_bytes.binding()))]);
        assert_eq!(
            minted(&provider, &sent).await,
            mismatch(BindingField::Digest)
        );
    }

    #[tokio::test]
    async fn a_receipt_at_another_tier_is_refused() {
        let provider = provider([Step::Forge(Forgery::Tier)]);
        let sent = fixtures::envelope(0, "actor-a");
        assert_eq!(minted(&provider, &sent).await, mismatch(BindingField::Tier));
    }

    #[tokio::test]
    async fn a_receipt_for_the_other_crossing_is_refused() {
        let provider = provider([Step::Forge(Forgery::Crossing)]);
        let sent = fixtures::envelope(0, "actor-a");
        assert_eq!(
            minted(&provider, &sent).await,
            mismatch(BindingField::Crossing)
        );
    }

    /// A provider answering with the receipt of the event it committed before: a stale
    /// receipt is another event's.
    #[tokio::test]
    async fn a_stale_receipt_from_the_previous_event_is_refused() {
        let provider = provider([Step::Commit, Step::ReplayPrevious]);
        let first = fixtures::envelope(0, "actor-a");
        assert_eq!(minted(&provider, &first).await, Ok(()));
        let second = fixtures::envelope(1, "actor-a");
        assert_eq!(
            minted(&provider, &second).await,
            mismatch(BindingField::EventId)
        );
    }

    #[tokio::test]
    async fn redeem_refuses_a_witness_for_another_event() {
        let sent = fixtures::envelope(0, "actor-a");
        let provider = provider([Step::Commit]);
        let witness = provider
            .commit::<Outcome>(&sent, bound())
            .await
            .expect("minted");
        let other = fixtures::envelope(1, "actor-a");
        assert_eq!(
            witness.redeem(&other, &provider).map(|_| ()),
            Err(WitnessRefusal::AnotherEvent)
        );
    }

    /// The same position in another run is another event: the run is part of the identity.
    #[tokio::test]
    async fn redeem_refuses_a_witness_from_another_run() {
        let sent = fixtures::envelope(0, "actor-a");
        let provider = provider([Step::Commit]);
        let witness = provider
            .commit::<Intent>(&sent, bound())
            .await
            .expect("minted");
        let other_run = fixtures::envelope_in(fixtures::OTHER_RUN, 0, "actor-a");
        assert_eq!(
            witness.redeem(&other_run, &provider).map(|_| ()),
            Err(WitnessRefusal::AnotherEvent)
        );
    }

    #[tokio::test]
    async fn redeem_refuses_a_witness_for_other_bytes() {
        let (sent, same_id_other_bytes) = fixtures::same_id_other_content();
        let provider = provider([Step::Commit]);
        let witness = provider
            .commit::<Intent>(&sent, bound())
            .await
            .expect("minted");
        assert_eq!(
            witness.redeem(&same_id_other_bytes, &provider).map(|_| ()),
            Err(WitnessRefusal::OtherContent)
        );
    }

    /// Two establishments of one authority are two providers: a witness from the earlier
    /// one is stale at a crossing that holds the later one.
    #[tokio::test]
    async fn redeem_refuses_a_witness_from_another_established_instance() {
        let authority = Arc::new(ReferenceAuthority::new(TIER));
        let earlier = EstablishedProvider::establish(authority.clone());
        let current = EstablishedProvider::establish(authority);
        let sent = fixtures::envelope(0, "actor-a");
        let witness = earlier
            .commit::<Intent>(&sent, bound())
            .await
            .expect("minted");
        assert_eq!(
            witness.redeem(&sent, &current).map(|_| ()),
            Err(WitnessRefusal::StaleProvider)
        );
    }
}
