// SPDX-License-Identifier: Apache-2.0
//! What the shared owner hands a commitment authority to commit.

use crate::audit_record::{AuditEnvelope, EventBinding};

use super::{CrossingKind, DurabilityTier};

/// One commitment request: the event's binding and canonical bytes, the crossing it gates,
/// and the tier the owner holds the provider to.
///
/// Borrowed and built only by the shared owner, so the bytes a provider is asked to store
/// and the binding the owner will check its receipt against are projections of ONE
/// envelope. A provider stores bytes, never the envelope.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CommitRequest<'a> {
    envelope: &'a AuditEnvelope,
    crossing: CrossingKind,
    tier: DurabilityTier,
}

impl<'a> CommitRequest<'a> {
    /// The request for `envelope` at `crossing`, held to `tier`.
    pub(super) fn new(
        envelope: &'a AuditEnvelope,
        crossing: CrossingKind,
        tier: DurabilityTier,
    ) -> Self {
        CommitRequest {
            envelope,
            crossing,
            tier,
        }
    }

    // The projections are crate-wide because `CommitmentAuthority` is: a provider anywhere
    // in the crate reads what it is asked to commit, and reading it grants nothing.

    /// The identity and digest the receipt must echo; a provider deduplicates on it.
    #[cfg_attr(not(test), allow(dead_code))] // read by providers; none is compiled outside tests
    pub(crate) fn binding(&self) -> EventBinding {
        self.envelope.binding()
    }

    /// The canonical bytes to store.
    #[cfg_attr(not(test), allow(dead_code))] // read by providers; none is compiled outside tests
    pub(crate) fn canonical_bytes(&self) -> &'a [u8] {
        self.envelope.canonical_bytes()
    }

    /// The crossing the receipt must echo.
    #[cfg_attr(not(test), allow(dead_code))] // read by providers; none is compiled outside tests
    pub(crate) fn crossing(&self) -> CrossingKind {
        self.crossing
    }

    /// The tier the provider was established at, which the receipt must echo.
    #[cfg_attr(not(test), allow(dead_code))] // read by providers; none is compiled outside tests
    pub(crate) fn tier(&self) -> DurabilityTier {
        self.tier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_commitment::fixtures;

    #[test]
    fn a_request_projects_exactly_one_envelope() {
        let envelope = fixtures::envelope(0, "actor-a");
        let request = CommitRequest::new(
            &envelope,
            CrossingKind::Outcome,
            DurabilityTier::ProcessVolatile,
        );
        assert_eq!(request.binding(), envelope.binding());
        assert_eq!(request.canonical_bytes(), envelope.canonical_bytes());
        assert_eq!(request.crossing(), CrossingKind::Outcome);
        assert_eq!(request.tier(), DurabilityTier::ProcessVolatile);
    }
}
