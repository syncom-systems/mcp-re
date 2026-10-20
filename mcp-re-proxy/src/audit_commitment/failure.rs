// SPDX-License-Identifier: Apache-2.0
//! What the shared owner reports when no witness was minted.

use super::{ProviderFailure, RejectReason};

/// Why a commitment produced no witness (ADR-MCPRE-070 §3). Exhaustive: no arm is a
/// success, and nothing here converts into one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitmentFailure {
    /// The provider refused the event: definitely not committed.
    Rejected(RejectReason),
    /// The provider was unreachable or out of capacity: definitely not committed.
    Unavailable,
    /// The answer is unknown or untrustworthy: the event may or may not be committed.
    Uncertain(UncertainCause),
}

/// Why a commitment is uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UncertainCause {
    /// The provider did not answer within the bound.
    TimedOut,
    /// The provider abandoned its completion after the send.
    Cancelled,
    /// The provider panicked, while building its future or while it was polled.
    ProviderPanicked,
    /// The provider answered with a receipt that does not match what was sent.
    ReceiptMismatch(BindingField),
}

/// Which part of a receipt disagreed with the request it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingField {
    /// Another event's identity.
    EventId,
    /// This identity with other content.
    Digest,
    /// The other crossing.
    Crossing,
    /// Another tier than the provider was established at.
    Tier,
}

impl CommitmentFailure {
    /// The owner's reading of a provider's own failure.
    pub(super) fn from_provider(failure: ProviderFailure) -> Self {
        match failure {
            ProviderFailure::Rejected(reason) => CommitmentFailure::Rejected(reason),
            ProviderFailure::Unavailable => CommitmentFailure::Unavailable,
            ProviderFailure::Cancelled => CommitmentFailure::Uncertain(UncertainCause::Cancelled),
        }
    }

    /// Whether the event may have been committed.
    ///
    /// Either way it is NOT committed for the prerequisite: no failure authorizes a
    /// crossing. `true` means it is possibly committed for IDENTITY, so its ID is never
    /// reused for other content and a retry resends the identical bytes (§3).
    #[cfg_attr(not(test), allow(dead_code))] // read by the reconciliation of an uncertain intent (#1205); G1 refuses on every failure alike
    pub(crate) fn possibly_committed(&self) -> bool {
        matches!(self, CommitmentFailure::Uncertain(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_and_unavailable_are_definitely_not_committed() {
        for failure in [
            CommitmentFailure::Rejected(RejectReason::IdentityConflict),
            CommitmentFailure::Rejected(RejectReason::Refused),
            CommitmentFailure::Unavailable,
        ] {
            assert!(!failure.possibly_committed(), "{failure:?}");
        }
    }

    #[test]
    fn every_uncertain_cause_is_possibly_committed() {
        for cause in [
            UncertainCause::TimedOut,
            UncertainCause::Cancelled,
            UncertainCause::ProviderPanicked,
            UncertainCause::ReceiptMismatch(BindingField::EventId),
            UncertainCause::ReceiptMismatch(BindingField::Digest),
            UncertainCause::ReceiptMismatch(BindingField::Crossing),
            UncertainCause::ReceiptMismatch(BindingField::Tier),
        ] {
            assert!(
                CommitmentFailure::Uncertain(cause).possibly_committed(),
                "{cause:?}"
            );
        }
    }

    /// A provider that dropped its acknowledgement may have written first, so its own
    /// `Cancelled` is uncertain, never a definite "not committed".
    #[test]
    fn a_provider_cancellation_is_uncertain_not_unavailable() {
        assert_eq!(
            CommitmentFailure::from_provider(ProviderFailure::Cancelled),
            CommitmentFailure::Uncertain(UncertainCause::Cancelled)
        );
        assert_eq!(
            CommitmentFailure::from_provider(ProviderFailure::Unavailable),
            CommitmentFailure::Unavailable
        );
        assert_eq!(
            CommitmentFailure::from_provider(ProviderFailure::Rejected(RejectReason::Refused)),
            CommitmentFailure::Rejected(RejectReason::Refused)
        );
    }
}
