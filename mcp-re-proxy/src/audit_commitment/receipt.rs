// SPDX-License-Identifier: Apache-2.0
//! What a commitment authority says it committed.

use crate::audit_record::EventBinding;

use super::{CrossingKind, DurabilityTier};

/// A provider's claim that it committed an event: which binding, at which crossing, at
/// which tier.
///
/// **Holding one authorizes nothing.** A receipt is the provider's `Ok`, and a provider's
/// bare `Ok` is not commitment (ADR-MCPRE-070 §3). It converts into no witness — there is
/// no `From`, no `Deref` and no accessor returning one — and it is not `Clone`: the shared
/// owner checks it once against the request it sent and only then mints a witness.
///
/// It carries no provider identity. The owner binds the provider instance it actually
/// called; an identity the provider reported about itself would be a claim, not a binding.
#[derive(Debug, PartialEq, Eq)]
pub struct CommitmentReceipt {
    binding: EventBinding,
    crossing: CrossingKind,
    tier: DurabilityTier,
}

impl CommitmentReceipt {
    /// A provider's receipt. `pub` because `CommitmentAuthority` is the embedder contract,
    /// and a receipt is the only thing a provider may answer with besides a failure:
    /// constructing one grants nothing until the owner has checked it.
    pub fn new(binding: EventBinding, crossing: CrossingKind, tier: DurabilityTier) -> Self {
        CommitmentReceipt {
            binding,
            crossing,
            tier,
        }
    }

    /// The binding the provider says it committed.
    pub(super) fn binding(&self) -> EventBinding {
        self.binding
    }

    /// The crossing the provider says it committed.
    pub(super) fn crossing(&self) -> CrossingKind {
        self.crossing
    }

    /// The tier the provider says it committed at.
    pub(super) fn tier(&self) -> DurabilityTier {
        self.tier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_commitment::fixtures;

    #[test]
    fn a_receipt_projects_exactly_what_it_was_built_from() {
        let binding = fixtures::envelope(3, "actor-a").binding();
        let receipt = CommitmentReceipt::new(
            binding,
            CrossingKind::Intent,
            DurabilityTier::SurvivesProxyProcessLoss,
        );
        assert_eq!(receipt.binding(), binding);
        assert_eq!(receipt.crossing(), CrossingKind::Intent);
        assert_eq!(receipt.tier(), DurabilityTier::SurvivesProxyProcessLoss);
    }
}
