// SPDX-License-Identifier: Apache-2.0
//! What a commitment provider may answer when it cannot be established.

/// Why a provider could not be established at startup — a CLASS, never text.
///
/// There is no message field, and that is the point: a provider's own error text may carry
/// a locator, a user name or a secret, and the startup refusal prints only the provider's
/// [`super::ProviderId`] and this class. Whatever the provider wants to say about its
/// settings it says through its own channel, not through the proxy's diagnostics.
///
/// `pub` because a provider answers its `establish` with it (the
/// [`super::CommitmentAuthority`] contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstablishFailure {
    /// The provider's store could not be reached.
    Unreachable,
    /// The provider's store refused its credentials.
    Unauthorized,
    /// The provider's own settings are missing or inconsistent.
    Misconfigured,
    /// The provider refused for a reason of its own.
    Refused,
}

impl EstablishFailure {
    /// The class, as the startup refusal prints it.
    pub(crate) fn wire_name(self) -> &'static str {
        match self {
            EstablishFailure::Unreachable => "UNREACHABLE",
            EstablishFailure::Unauthorized => "UNAUTHORIZED",
            EstablishFailure::Misconfigured => "MISCONFIGURED",
            EstablishFailure::Refused => "REFUSED",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_has_a_distinct_wire_name() {
        let all = [
            EstablishFailure::Unreachable,
            EstablishFailure::Unauthorized,
            EstablishFailure::Misconfigured,
            EstablishFailure::Refused,
        ];
        let names: std::collections::BTreeSet<_> = all.iter().map(|c| c.wire_name()).collect();
        assert_eq!(names.len(), all.len());
    }
}
