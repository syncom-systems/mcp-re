// SPDX-License-Identifier: Apache-2.0
//! The reference authority's forged receipts. Test-only flavors, like the authority.

#[cfg(test)]
use crate::audit_record::EventBinding;

use super::{CommitRequest, CommitmentReceipt, CrossingKind, DurabilityTier};

/// How a forged receipt disagrees with its request.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Forgery {
    /// Another binding. Unit tests only: a serving suite cannot name another event's binding.
    #[cfg(test)]
    Binding(EventBinding),
    /// The other crossing.
    Crossing,
    /// The other tier.
    Tier,
}

pub(super) fn forged(forgery: Forgery, request: &CommitRequest<'_>) -> CommitmentReceipt {
    let (binding, crossing, tier) = (request.binding(), request.crossing(), request.tier());
    match forgery {
        #[cfg(test)]
        Forgery::Binding(other) => CommitmentReceipt::new(other, crossing, tier),
        Forgery::Crossing => CommitmentReceipt::new(binding, other_crossing(crossing), tier),
        Forgery::Tier => {
            let other = match tier {
                DurabilityTier::ProcessVolatile => DurabilityTier::SurvivesProxyProcessLoss,
                DurabilityTier::SurvivesProxyProcessLoss => DurabilityTier::ProcessVolatile,
            };
            CommitmentReceipt::new(binding, crossing, other)
        }
    }
}

/// A crossing other than `crossing`.
fn other_crossing(crossing: CrossingKind) -> CrossingKind {
    match crossing {
        CrossingKind::Intent => CrossingKind::Outcome,
        CrossingKind::Outcome | CrossingKind::Accounting => CrossingKind::Intent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each forgery changes exactly the field it names.
    #[test]
    fn a_forged_crossing_names_another_crossing() {
        for (kind, other) in [
            (CrossingKind::Intent, CrossingKind::Outcome),
            (CrossingKind::Outcome, CrossingKind::Intent),
            (CrossingKind::Accounting, CrossingKind::Intent),
        ] {
            assert_eq!(other_crossing(kind), other);
        }
    }
}
