// SPDX-License-Identifier: Apache-2.0
//! Envelopes for the commitment tests, produced through the real producer. Test-only: this
//! module is declared `#[cfg(test)]`.

use crate::admission_enforcer::AdmissionFacet;
use crate::audit_record::{
    AuditEnvelope, AuditRecord, AuditSubject, CanonicalEvent, EventAllocator, RunId,
};
use crate::authorization::AuthorizationPosture;

/// The run every fixture is numbered in unless it names another.
pub(crate) const RUN: RunId = RunId::fixed([0x5c; 16]);
/// A second run.
pub(crate) const OTHER_RUN: RunId = RunId::fixed([0xc5; 16]);

fn accepted(actor: &str) -> AuditRecord {
    AuditRecord {
        subject: AuditSubject::request_accepted(
            &AuthorizationPosture::NoPolicyConfigured,
            AdmissionFacet::LiveConfirmed,
        ),
        actor_id: Some(actor.into()),
        status: 200,
        at_unix: 10,
    }
}

/// The `seq`-th event of `run`, accepting `actor`'s request.
pub(crate) fn envelope_in(run: RunId, seq: i64, actor: &str) -> CanonicalEvent {
    AuditEnvelope::produce_for_test(
        &EventAllocator::starting_at(run, seq),
        None,
        accepted(actor),
    )
    .expect("produced")
    .event()
    .clone()
}

/// The `seq`-th event of [`RUN`], accepting `actor`'s request.
pub(crate) fn envelope(seq: i64, actor: &str) -> CanonicalEvent {
    envelope_in(RUN, seq, actor)
}

/// One identity carrying two contents: the reused-run hazard.
pub(crate) fn same_id_other_content() -> (CanonicalEvent, CanonicalEvent) {
    (envelope(0, "actor-a"), envelope(0, "actor-b"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_conflicting_pair_shares_an_identity_and_not_its_content() {
        let (first, second) = same_id_other_content();
        assert_eq!(first.id(), second.id());
        assert_ne!(first.digest(), second.digest());
        assert_ne!(
            envelope(0, "actor-a").id(),
            envelope_in(OTHER_RUN, 0, "actor-a").id()
        );
    }
}
