// SPDX-License-Identifier: Apache-2.0
//! What an exchange holds at the intent crossing (ADR-MCPRE-070 G1, D7), carried across the
//! dispatch boundary.
//!
//! The runtime carrier of the audit-commitment machine A (§4): the ready state cannot be
//! built without one of these, so under the required posture no dispatch exists without a
//! committed intent redeemed for THIS exchange. The model A is stated, and checked against
//! the request machine, in `crate::audit_commitment::machine`.

use crate::audit_commitment::{NoCommitmentRequired, OwedOutcome};

/// The intent obligation, as a closed set.
///
/// # Why this is not `Option<Redeemed<Intent>>`
///
/// For the reason [`RetentionDisposition`](super::RetentionDisposition) is not an `Option`:
/// `None` would mean BOTH "this deployment requires no commitment" and "this deployment
/// requires one, and it is missing", and the second is a bypassed crossing. Each arm here
/// carries its owner's product, so neither can be written by the code that holds it.
#[derive(Debug)]
pub(crate) enum IntentDisposition {
    /// The deployment runs the best-effort posture. The posture owner's statement that no
    /// commitment was owed — never a fake witness.
    NotRequired(NoCommitmentRequired),
    /// A committed execution intent, redeemed for this exchange's event against the
    /// provider the posture holds, and the outcome it leaves owed. Held across the dispatch
    /// and spent by the outcome crossing (G2), which commits for the coordinate the intent
    /// named (D9) and to the provider it was committed to, reading neither again.
    Committed(OwedOutcome),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The intent obligation has exactly two cases, and a consumer matches them
    /// exhaustively: there is no "required but missing" to detect at runtime.
    #[test]
    fn the_intent_obligation_has_exactly_two_cases() {
        let disposition = IntentDisposition::NotRequired(NoCommitmentRequired::for_a_test());
        let committed = match disposition {
            IntentDisposition::NotRequired(_) => false,
            IntentDisposition::Committed(_) => true,
        };
        assert!(!committed, "a best-effort deployment committed nothing");
    }
}
