// SPDX-License-Identifier: Apache-2.0
//! What an exchange holds at the outcome crossing (ADR-MCPRE-070 G2, D4, Q2), carried to the
//! success exit.
//!
//! The success exit cannot serve without one of these, so under the required posture no
//! success is visible without the exchange's outcome committed and redeemed. It is obtained
//! only from `IntentDisposition::outcome`, so requiredness is the
//! [`IntentDisposition`](super::IntentDisposition) G1 carried across the dispatch.

use crate::audit_commitment::{CommittedOutcome, NoCommitmentRequired};

/// The outcome obligation, as a closed set.
///
/// Not an `Option`, for the reason [`IntentDisposition`](super::IntentDisposition) is not:
/// `None` would mean both "no commitment was owed" and "one was owed and is missing".
#[derive(Debug)]
pub(crate) enum OutcomeDisposition {
    /// The exchange was dispatched under the best-effort posture, and the posture owner's
    /// statement that nothing was owed is passed through from G1. Nothing was produced: the
    /// response record is produced when the response is served, as before.
    NotRequired(NoCommitmentRequired),
    /// The exchange's `response.signed` event, committed and redeemed. The success exit
    /// offers exactly these bytes to the observer. Boxed: the event is large and the
    /// best-effort arm is empty.
    Committed(Box<CommittedOutcome>),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The outcome obligation has exactly two cases, and the success exit matches them
    /// exhaustively: there is no "required but missing" to detect at runtime.
    #[test]
    fn the_outcome_obligation_has_exactly_two_cases() {
        let disposition = OutcomeDisposition::NotRequired(NoCommitmentRequired::for_a_test());
        let committed = match disposition {
            OutcomeDisposition::NotRequired(_) => false,
            OutcomeDisposition::Committed(_) => true,
        };
        assert!(!committed, "a best-effort exchange committed nothing");
    }
}
