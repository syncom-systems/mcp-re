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
//! type establishes (D3). The reference authority in `reference` exists only in test builds
//! and the test-only `audit_commitment_reference` flavor.
//!
//! # The embedder seam (#1206)
//!
//! An independently compiled provider implements [`CommitmentAuthority`] and a build
//! registers it in [`AuditProviders`], which `app::run_with` takes. [`AuditPlan`] resolves
//! the operator's `--audit-commitment` against what was registered, purely and before any
//! effect; establishment reads the declared tier once, refuses one below the minimum, and
//! bounds the provider's own probe. Any failure refuses startup — a required posture is never
//! served as best-effort (S4). The provider-facing types are `pub`, and that is the whole
//! external contract: a provider can produce a receipt, a failure, a name and an
//! establishment class, and never a witness.
//!
//! # The crossing and the posture
//!
//! [`AuditPosture`] is what the serving path holds: the observer, and whether G1 is a
//! prerequisite. Under the required posture its intent crossing (`intent`) commits the
//! exchange's [`ExecutionIntent`](crate::audit_record::ExecutionIntent) and redeems the
//! witness, and the ready state cannot be built without the result. Under the best-effort
//! posture it hands out [`NoCommitmentRequired`] instead, and commits nothing.

/// The commitment path's own counters and budget, and the shutdown report.
mod accounting;
/// The provider seam.
mod authority;
/// The bounded wait.
mod bound;
/// The commitment budget (§7.4).
mod budget;
/// The accounting record's cadence (D2, Q3).
mod cadence;
/// The crossing kinds, as values and as types.
mod crossing;
/// What a provider answers when it cannot be established.
mod establish_failure;
/// The established provider, the commit procedure, and the witness.
mod established;
/// The commitment half of the posture, once established.
mod established_audit;
/// The owner's typed failure.
mod failure;
/// G1: the intent crossing's procedure.
mod intent;
/// The best-effort posture's statement that nothing is owed.
mod not_required;
/// G2: the outcome crossing's procedure.
mod outcome;
/// The requested policy resolved against the registered providers.
mod plan;
/// The deployment's audit posture: observer and commitment.
mod posture;
/// The provider's typed failure.
mod provider_failure;
/// A provider's printable name.
mod provider_id;
/// What a build registers: the injection seam.
mod providers;
/// What a provider says it committed.
mod receipt;
/// Why the required posture refuses startup.
mod refusal;
/// What a provider is asked to commit.
mod request;
/// The declared durability tier.
mod tier;

/// Envelopes the commitment tests commit. Test-only.
#[cfg(test)]
pub(crate) mod fixtures;
/// The reference authority's forged receipts. Test-only flavors.
#[cfg(any(test, feature = "audit_commitment_reference"))]
mod forgery;
/// The reference authority as the serving integration tests drive it. Test-only flavors.
#[cfg(any(test, feature = "audit_commitment_reference"))]
mod harness;
/// The model of the audit-commitment machine A, checked against R and the G1 types.
#[cfg(test)]
mod machine;
/// The deterministic, scripted reference authority. Test-only flavors.
#[cfg(any(test, feature = "audit_commitment_reference"))]
pub(crate) mod reference;
/// The reference authority's startup probe. Test-only flavors.
#[cfg(any(test, feature = "audit_commitment_reference"))]
mod reference_probe;
/// The reference authority's script. Test-only flavors.
#[cfg(any(test, feature = "audit_commitment_reference"))]
mod reference_step;

// The embedder contract (#1206): what an independently compiled provider implements,
// reads, answers with and is registered through. `pub`, and re-exported at the crate root.
pub use authority::{CommitFuture, CommitmentAuthority, EstablishFuture};
pub use crossing::CrossingKind;
pub use establish_failure::EstablishFailure;
pub use provider_failure::{ProviderFailure, RejectReason};
pub use provider_id::ProviderId;
pub use providers::AuditProviders;
pub use receipt::CommitmentReceipt;
pub use request::CommitRequest;
pub use tier::DurabilityTier;
pub(crate) use tier::TIER_VOCABULARY;

pub(crate) use bound::CommitmentBound;
pub(crate) use budget::BUDGET_CEILING;
pub(crate) use cadence::{run as run_accounting_cadence, ACCOUNTING_INTERVAL};
pub(crate) use crossing::{Accounting, Crossing, Intent, Outcome};
pub(crate) use established::EstablishedProvider;
pub(crate) use established::Redeemed;
pub(crate) use established_audit::EstablishedAudit;
pub(crate) use outcome::OwedOutcome;
// What a crossing spends and why it may refuse: no code outside `established` names these
// yet, in any build.
#[allow(unused_imports)]
pub(crate) use established::{CommitmentWitness, WitnessRefusal};
pub(crate) use failure::{BindingField, CommitmentFailure, UncertainCause};
#[cfg(any(test, feature = "audit_commitment_reference"))]
pub(crate) use harness::establish_reference;
#[cfg(any(test, feature = "audit_commitment_reference"))]
pub use harness::{ReferenceCommitment, ScriptedAnswer};
pub(crate) use not_required::NoCommitmentRequired;
pub(crate) use outcome::CommittedOutcome;
pub(crate) use plan::AuditPlan;
pub(crate) use posture::AuditPosture;
pub(crate) use refusal::AuditPostureRefusal;

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
        EstablishedProvider::eligible_for_test(Arc::new(
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
