// SPDX-License-Identifier: Apache-2.0
//! Why a produced record received no event identity.

use super::RunId;

/// Why a record could not be given an identity, and so reached no sink as an event.
///
/// Every arm is a stated failure rather than a fallback: no arm wraps a sequence, reuses an
/// identity, or invents an exchange coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventIdentityFailure {
    /// The run has handed out every `seq` it has. Permanent for the run: the allocator
    /// never wraps, so no later record of this run is numbered either.
    SequenceExhausted {
        /// The run that is exhausted.
        run: RunId,
    },
    /// No run could be drawn, because the OS CSPRNG failed.
    RunUnavailable,
    /// The record's half and decision admit no scope with the exchange coordinate it was
    /// produced with: a response with no accepted exchange, a request given one, or a
    /// coordinate from another run or from a later event.
    ScopeRefused,
    /// The record has more fields, or a longer value, than the canonical form can delimit.
    Unencodable,
}

impl std::fmt::Display for EventIdentityFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventIdentityFailure::SequenceExhausted { run } => {
                write!(f, "the sequence of run {run} is exhausted")
            }
            EventIdentityFailure::RunUnavailable => f.write_str("no run could be drawn"),
            EventIdentityFailure::ScopeRefused => {
                f.write_str("the record has no scope under its exchange coordinate")
            }
            EventIdentityFailure::Unencodable => {
                f.write_str("the record exceeds the canonical form's delimiters")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_states_its_own_cause() {
        let run = RunId::fixed([0xab; 16]);
        let stated = [
            EventIdentityFailure::SequenceExhausted { run },
            EventIdentityFailure::RunUnavailable,
            EventIdentityFailure::ScopeRefused,
            EventIdentityFailure::Unencodable,
        ]
        .map(|f| f.to_string());
        assert_eq!(
            stated[0],
            "the sequence of run abababababababababababababababab is exhausted"
        );
        let mut distinct = stated.to_vec();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), stated.len(), "{stated:?}");
    }
}
