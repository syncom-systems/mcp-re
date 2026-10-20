// SPDX-License-Identifier: Apache-2.0
//! Required durable audit commitment: a separate authority from the observer
//! (ADR-MCPRE-070 §2, §3, §9).
//!
//! # Two contracts, not one
//!
//! ```text
//! observer   AuditSink::record(&envelope) -> ()        absorbs its failures; authorizes nothing
//! authority  CommitmentAuthority::commit(request)      -> receipt | ProviderFailure
//!              └─ EstablishedProvider::commit::<K>     -> CommitmentWitness<K> | CommitmentFailure
//!                   └─ CommitmentWitness::redeem       -> Redeemed<K> | WitnessRefusal
//! ```
//!
//! The observer ([`crate::audit_sink`]) is unchanged: whatever it does — writes, drops,
//! panics, or is not installed — it never fails a request and nothing it returns is evidence
//! of commitment. A crossing that requires commitment requires a [`Redeemed`], and the only
//! route to one runs through this module.
//!
//! # Who decides what
//!
//! * **The provider** ([`CommitmentAuthority`]) answers with a [`CommitmentReceipt`] or a
//!   [`ProviderFailure`]. A receipt is a claim and authorizes nothing.
//! * **The shared owner** ([`EstablishedProvider`]) sends the request, bounds the wait,
//!   catches the provider's panic, and checks the receipt against the envelope it sent: the
//!   event's identity and digest, the crossing, and the tier the provider declared when it
//!   was established. Only then does it mint a [`CommitmentWitness`], bound to that provider
//!   instance. Its constructor is private to `established`, so this owner is the sole
//!   producer of the value.
//! * **The crossing** spends the witness once, by move, against the event it is about and
//!   the provider it holds now. A witness for another event, other bytes, another run or
//!   another established instance is refused.
//!
//! # What none of it proves
//!
//! Whether the provider persisted anything. A witness proves the shared code's handling and
//! binding of the provider's answer; the provider's declared [`DurabilityTier`] is an
//! assumption that needs external evidence per provider, and is never a property a Rust
//! type establishes (D3). The reference authority in `reference` exists only in this
//! crate's unit tests.

/// The provider seam.
mod authority;
/// The bounded wait.
mod bound;
/// The crossing kinds, as values and as types.
mod crossing;
/// The established provider, the commit procedure, and the witness.
mod established;
/// The owner's typed failure.
mod failure;
/// The provider's typed failure.
mod provider_failure;
/// What a provider says it committed.
mod receipt;
/// What a provider is asked to commit.
mod request;
/// The declared durability tier.
mod tier;

/// Envelopes the commitment tests commit. Test-only.
#[cfg(test)]
pub(crate) mod fixtures;
/// The deterministic, scripted reference authority. Test-only.
#[cfg(test)]
pub(crate) mod reference;

pub(crate) use authority::{CommitFuture, CommitmentAuthority};
pub(crate) use bound::CommitmentBound;
pub(crate) use crossing::{Crossing, CrossingKind};
// The names a crossing holds. No production crossing commits yet, so outside the crate's
// unit tests nothing imports them.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use crossing::{Intent, Outcome};
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use established::EstablishedProvider;
// What a crossing spends and what it keeps: no code outside `established` names these yet,
// in any build.
#[allow(unused_imports)]
pub(crate) use established::{CommitmentWitness, Redeemed, WitnessRefusal};
pub(crate) use failure::{BindingField, CommitmentFailure, UncertainCause};
pub(crate) use provider_failure::{ProviderFailure, RejectReason};
pub(crate) use receipt::CommitmentReceipt;
pub(crate) use request::CommitRequest;
pub(crate) use tier::DurabilityTier;

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::fixtures;
    use super::reference::{ReferenceAuthority, Step};
    use super::*;
    use crate::admission_enforcer::AdmissionFacet;
    use crate::audit_record::{AuditEnvelope, AuditSubject, EventIdentityFailure};
    use crate::audit_sink::{AuditSink, MaybeAuditSink};

    struct PanickingSink;

    impl AuditSink for PanickingSink {
        fn record(&self, _envelope: &AuditEnvelope) {
            panic!("observer fault");
        }

        fn unnumbered(&self, _failure: &EventIdentityFailure) {
            panic!("observer fault");
        }
    }

    fn provider(step: Step) -> Arc<EstablishedProvider> {
        EstablishedProvider::establish(Arc::new(
            ReferenceAuthority::new(DurabilityTier::SurvivesProxyProcessLoss).scripted([step]),
        ))
    }

    fn bound() -> CommitmentBound {
        CommitmentBound::new(Duration::from_secs(1)).expect("legal bound")
    }

    /// The observer's fault is absorbed and changes nothing about commitment: the request
    /// is not failed, and the commitment answers on its own terms.
    #[tokio::test]
    async fn a_panicking_observer_neither_fails_nor_authorizes_a_commitment() {
        let observer: MaybeAuditSink = Some(Arc::new(PanickingSink));
        let accepted = AuditSubject::request_accepted(
            &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
            AdmissionFacet::NotConfigured,
        );
        let exchange = crate::audit_record::record_to(&observer, None, accepted, None, 200, 1);
        assert!(
            exchange.is_some(),
            "the observer's panic did not fail the request"
        );

        let envelope = fixtures::envelope(0, "actor-a");
        let committed = provider(Step::Commit)
            .commit::<Intent>(&envelope, bound())
            .await;
        assert!(committed.is_ok());
        let refused = provider(Step::Unavailable)
            .commit::<Intent>(&envelope, bound())
            .await;
        assert_eq!(
            refused.map(|_| ()),
            Err(CommitmentFailure::Unavailable),
            "an observer that 'succeeded' does not stand in for an authority that refused"
        );
    }

    /// The authority's panic is the opposite kind of fact: a typed failure, not a swallow.
    #[tokio::test]
    async fn a_panicking_authority_is_typed_not_swallowed() {
        let envelope = fixtures::envelope(0, "actor-a");
        assert_eq!(
            provider(Step::PanicInPoll)
                .commit::<Intent>(&envelope, bound())
                .await
                .map(|_| ()),
            Err(CommitmentFailure::Uncertain(
                UncertainCause::ProviderPanicked
            ))
        );
    }
}
