// SPDX-License-Identifier: Apache-2.0
//! What a commitment authority may answer instead of a receipt.

/// A provider's typed refusal to produce a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // constructed by providers; none is compiled outside tests
pub(crate) enum ProviderFailure {
    /// The provider refused the event: definitely not committed.
    Rejected(RejectReason),
    /// The provider is unreachable, full or over quota: definitely not committed.
    Unavailable,
    /// The provider abandoned its in-flight completion after the send (its acknowledgement
    /// was dropped): possibly committed.
    Cancelled,
}

/// Why a provider refused an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // constructed by providers; none is compiled outside tests
pub(crate) enum RejectReason {
    /// The identity is already committed with another digest: an integrity conflict
    /// (ADR-MCPRE-070 §8), never an overwrite.
    IdentityConflict,
    /// Any other refusal the provider states.
    Refused,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rejection_names_its_reason() {
        assert_ne!(
            ProviderFailure::Rejected(RejectReason::IdentityConflict),
            ProviderFailure::Rejected(RejectReason::Refused)
        );
        assert_ne!(ProviderFailure::Unavailable, ProviderFailure::Cancelled);
    }
}
