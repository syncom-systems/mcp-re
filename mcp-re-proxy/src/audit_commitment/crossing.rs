// SPDX-License-Identifier: Apache-2.0
//! Which crossing a commitment gates: the intent before dispatch (G1) or the outcome before
//! visible success (G2).

/// Which crossing, as a value: what a provider echoes in its receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrossingKind {
    /// The execution intent, committed before dispatch (G1).
    Intent,
    /// The outcome, committed before success is visible (G2).
    Outcome,
}

mod sealed {
    /// Closes [`super::Crossing`] to the two markers below.
    pub trait Sealed {}
    impl Sealed for super::Intent {}
    impl Sealed for super::Outcome {}
}

/// Which crossing, as a type: a witness for one cannot be passed where the other is
/// required. Sealed, so the two markers are the only crossings.
pub(crate) trait Crossing: sealed::Sealed {
    /// The value a receipt for this crossing must echo.
    const KIND: CrossingKind;
}

/// The intent crossing (G1). Uninhabited: it exists only as a type parameter.
#[derive(Debug)]
pub(crate) enum Intent {}

/// The outcome crossing (G2). Uninhabited: it exists only as a type parameter.
#[derive(Debug)]
pub(crate) enum Outcome {}

impl Crossing for Intent {
    const KIND: CrossingKind = CrossingKind::Intent;
}

impl Crossing for Outcome {
    const KIND: CrossingKind = CrossingKind::Outcome;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_and_outcome_have_distinct_kinds() {
        assert_eq!(Intent::KIND, CrossingKind::Intent);
        assert_eq!(Outcome::KIND, CrossingKind::Outcome);
        assert_ne!(Intent::KIND, Outcome::KIND);
    }
}
