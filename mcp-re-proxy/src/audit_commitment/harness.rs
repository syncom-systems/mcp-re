// SPDX-License-Identifier: Apache-2.0
//! The reference authority, as the serving integration tests drive it.
//!
//! Compiled only into test builds and the test-only `audit_commitment_reference` flavor
//! (`scripts/fixture_feature_gate.py` refuses that feature on any non-test target), so no
//! deployable library contains it. It is `pub` because the integration suites are another
//! crate; it widens nothing in `:mcp_re_proxy`, which does not compile it.
//!
//! The surface is a script and two readings. It hands out no provider, receipt or witness:
//! the only thing a test can do with a [`ReferenceCommitment`] is install it as the required
//! posture's authority (`HttpProfileProxy::with_required_audit_commitment`), which runs it
//! through the same established-provider checks as any provider.

use std::sync::Arc;

use super::reference::{Forgery, Hook, ReferenceAuthority, Step};
use super::{CommitmentAuthority, DurabilityTier, RejectReason};
use crate::audit_record::{EventId, ExchangeCoordinate};

/// One scripted answer of the reference authority. An exhausted script commits.
#[derive(Clone)]
pub enum ScriptedAnswer {
    /// Journal the event and acknowledge it.
    Commit,
    /// Refuse the event.
    Reject,
    /// Report the provider unavailable.
    Unavailable,
    /// Never answer.
    Hang,
    /// Drop the acknowledgement after the send.
    DropCompletion,
    /// Panic while the answer is polled.
    PanicInPoll,
    /// Panic before any answer exists.
    PanicBeforeFuture,
    /// Acknowledge with a receipt for the other crossing.
    ForgeReceipt,
    /// Acknowledge with a receipt at another tier than the authority declared.
    ForgeTier,
    /// Acknowledge with the receipt of the previous commit.
    ReplayPrevious,
    /// Journal the event, then never acknowledge.
    CommitThenPark,
    /// Journal the event, run the hook, then acknowledge.
    CommitThen(Arc<dyn Fn() + Send + Sync>),
}

impl ScriptedAnswer {
    fn step(self) -> Step {
        match self {
            ScriptedAnswer::Commit => Step::Commit,
            ScriptedAnswer::Reject => Step::Reject(RejectReason::Refused),
            ScriptedAnswer::Unavailable => Step::Unavailable,
            ScriptedAnswer::Hang => Step::Hang,
            ScriptedAnswer::DropCompletion => Step::DropCompletion,
            ScriptedAnswer::PanicInPoll => Step::PanicInPoll,
            ScriptedAnswer::PanicBeforeFuture => Step::PanicBeforeFuture,
            ScriptedAnswer::ForgeReceipt => Step::Forge(Forgery::Crossing),
            ScriptedAnswer::ForgeTier => Step::Forge(Forgery::Tier),
            ScriptedAnswer::ReplayPrevious => Step::ReplayPrevious,
            ScriptedAnswer::CommitThenPark => Step::CommitThenPark,
            ScriptedAnswer::CommitThen(hook) => Step::CommitThen(Hook(hook)),
        }
    }
}

/// A scripted reference commitment authority, and what it was asked.
#[derive(Debug, Clone)]
pub struct ReferenceCommitment {
    authority: Arc<ReferenceAuthority>,
}

impl ReferenceCommitment {
    /// An authority declaring the tier the required posture accepts, answering `script`.
    pub fn surviving_process_loss(script: impl IntoIterator<Item = ScriptedAnswer>) -> Self {
        Self::declaring(DurabilityTier::SurvivesProxyProcessLoss, script)
    }

    /// An authority declaring a volatile tier, which the required posture refuses (D3).
    pub fn process_volatile() -> Self {
        Self::declaring(DurabilityTier::ProcessVolatile, [])
    }

    fn declaring(tier: DurabilityTier, script: impl IntoIterator<Item = ScriptedAnswer>) -> Self {
        ReferenceCommitment {
            authority: Arc::new(
                ReferenceAuthority::new(tier)
                    .scripted(script.into_iter().map(ScriptedAnswer::step)),
            ),
        }
    }

    /// How many commits the authority was asked for, whatever it answered.
    pub fn requests(&self) -> usize {
        self.authority.requests()
    }

    /// Every event the authority journaled, in order: its identity, and the exchange it
    /// names.
    pub fn journaled(&self) -> Vec<(EventId, Option<ExchangeCoordinate>)> {
        self.authority.journaled()
    }

    /// The authority, for the installer.
    pub(crate) fn authority(&self) -> Arc<dyn CommitmentAuthority> {
        self.authority.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_reference_has_been_asked_nothing() {
        let reference = ReferenceCommitment::surviving_process_loss([ScriptedAnswer::Commit]);
        assert_eq!(reference.requests(), 0);
        assert!(reference.journaled().is_empty());
        assert_eq!(
            reference.authority().declared_tier(),
            DurabilityTier::SurvivesProxyProcessLoss
        );
        assert_eq!(
            ReferenceCommitment::process_volatile()
                .authority()
                .declared_tier(),
            DurabilityTier::ProcessVolatile
        );
    }

    /// Every scripted answer maps to its own step, and none silently becomes a commit.
    #[test]
    fn each_answer_maps_to_its_own_step() {
        let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
        let steps: Vec<String> = [
            ScriptedAnswer::Commit,
            ScriptedAnswer::Reject,
            ScriptedAnswer::Unavailable,
            ScriptedAnswer::Hang,
            ScriptedAnswer::DropCompletion,
            ScriptedAnswer::PanicInPoll,
            ScriptedAnswer::PanicBeforeFuture,
            ScriptedAnswer::ForgeReceipt,
            ScriptedAnswer::ForgeTier,
            ScriptedAnswer::ReplayPrevious,
            ScriptedAnswer::CommitThenPark,
            ScriptedAnswer::CommitThen(hook),
        ]
        .into_iter()
        .map(|answer| format!("{:?}", answer.step()))
        .collect();
        let distinct: std::collections::BTreeSet<_> = steps.iter().collect();
        assert_eq!(distinct.len(), steps.len(), "{steps:?}");
    }
}
