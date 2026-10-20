// SPDX-License-Identifier: Apache-2.0
//! Which exchange an event belongs to (ADR-MCPRE-070 D9).

use mcp_re_core::audit::{AuditHalf, Decision};

use super::{EventId, EventIdentityFailure};
use crate::audit_record::AuditRecord;

/// The stable coordinate of one exchange: the identity of its `request.accepted` event.
///
/// It needs no counter of its own and carries nothing read from the wire — no request
/// digest, no nonce — so it says which exchange an event belongs to without disclosing
/// anything about the request (ADR-MCPS-020). Its only producer is the envelope of an
/// accepted request, so a coordinate is never a fabricated accepted identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExchangeCoordinate(EventId);

impl ExchangeCoordinate {
    /// The coordinate an accepted request's own identity establishes.
    pub(super) fn of_accepted(id: EventId) -> Self {
        ExchangeCoordinate(id)
    }

    /// The identity of the `request.accepted` event this coordinate names.
    pub fn accepted_event(&self) -> EventId {
        self.0
    }
}

/// Which exchange an event is about, decided from the event and never supplied as a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventScope {
    /// A `request.accepted` event: it opens an exchange, and its own identity is that
    /// exchange's coordinate.
    Origin,
    /// A response event of an accepted exchange, naming the exchange's coordinate.
    Exchange(ExchangeCoordinate),
    /// A `request.rejected` event: refused before any exchange was accepted, so there is no
    /// accepted identity to name and none is invented.
    PreAcceptance,
}

impl EventScope {
    /// The scope of `record`, numbered `id`, produced under `link`.
    ///
    /// | record | link | scope |
    /// |---|---|---|
    /// | request half, accepted | none | `Origin` |
    /// | request half, rejected | none | `PreAcceptance` |
    /// | response half | an earlier event of the same run | `Exchange` |
    ///
    /// Every other pairing is refused: a response with no accepted exchange is never given
    /// one, a request is never attached to another exchange, and a coordinate from another
    /// run or from a later event names no exchange this event can belong to.
    pub(super) fn derive(
        record: &AuditRecord,
        id: &EventId,
        link: Option<ExchangeCoordinate>,
    ) -> Result<EventScope, EventIdentityFailure> {
        let event = record.event();
        match (event.half(), event.decision(), link) {
            (AuditHalf::Request, Decision::Accepted, None) => Ok(EventScope::Origin),
            (AuditHalf::Request, Decision::Rejected, None) => Ok(EventScope::PreAcceptance),
            (AuditHalf::Response, _, Some(c)) if precedes_in_run(&c.0, id) => {
                Ok(EventScope::Exchange(c))
            }
            _ => Err(EventIdentityFailure::ScopeRefused),
        }
    }
}

impl EventScope {
    /// The scope of an execution intent numbered `id`: the exchange `coordinate` names
    /// (ADR-MCPRE-070 D9).
    ///
    /// An intent always belongs to an accepted exchange, so there is no intent without a
    /// coordinate, and a coordinate from another run or from a later event is refused for
    /// the reason [`EventScope::derive`] refuses it. Visible to the intent's producer in
    /// `audit_record`, which is the one caller.
    pub(in crate::audit_record) fn of_intent(
        id: &EventId,
        coordinate: ExchangeCoordinate,
    ) -> Result<EventScope, EventIdentityFailure> {
        if precedes_in_run(&coordinate.0, id) {
            Ok(EventScope::Exchange(coordinate))
        } else {
            Err(EventIdentityFailure::ScopeRefused)
        }
    }
}

/// Whether `earlier` was generated before `later` in the same run.
fn precedes_in_run(earlier: &EventId, later: &EventId) -> bool {
    let ((run_a, seq_a), (run_b, seq_b)) = (earlier.parts(), later.parts());
    run_a == run_b && seq_a < seq_b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_enforcer::AdmissionFacet;
    use crate::audit_record::envelope::RunId;
    use crate::audit_record::AuditSubject;
    use crate::authorization::{
        AuthorizationFacet, AuthorizationPosture, AuthorizationRefusalFacet,
    };

    const RUN: RunId = RunId::fixed([0x11; 16]);

    fn record(subject: AuditSubject) -> AuditRecord {
        AuditRecord {
            subject,
            actor_id: None,
            status: 200,
            at_unix: 1,
        }
    }

    fn accepted() -> AuditRecord {
        record(AuditSubject::request_accepted(
            &AuthorizationPosture::NoPolicyConfigured,
            AdmissionFacet::NotConfigured,
        ))
    }

    fn rejected() -> AuditRecord {
        record(AuditSubject::request_rejected(
            Some(&mcp_re_core::McpReError::ReplayDetected),
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
            AdmissionFacet::NotReached,
        ))
    }

    fn link(run: RunId, seq: i64) -> Option<ExchangeCoordinate> {
        Some(ExchangeCoordinate::of_accepted(EventId::new(run, seq)))
    }

    #[test]
    fn each_half_and_decision_takes_its_own_scope() {
        let id = EventId::new(RUN, 5);
        assert_eq!(
            EventScope::derive(&accepted(), &id, None),
            Ok(EventScope::Origin)
        );
        assert_eq!(
            EventScope::derive(&rejected(), &id, None),
            Ok(EventScope::PreAcceptance)
        );
        for response in [
            AuditSubject::response_signed(),
            AuditSubject::response_rejected(Some(&mcp_re_core::McpReError::DigestMismatch)),
            AuditSubject::response_rejected(None),
        ] {
            assert_eq!(
                EventScope::derive(&record(response), &id, link(RUN, 3)),
                Ok(EventScope::Exchange(
                    link(RUN, 3).expect("a coordinate was given")
                ))
            );
        }
    }

    /// D9: an event with no accepted exchange is never given one, and a request is never
    /// attached to another exchange.
    #[test]
    fn no_accepted_identity_is_fabricated_or_borrowed() {
        let id = EventId::new(RUN, 5);
        let signed = record(AuditSubject::response_signed());
        let refused = Err(EventIdentityFailure::ScopeRefused);
        assert_eq!(EventScope::derive(&signed, &id, None), refused);
        assert_eq!(EventScope::derive(&accepted(), &id, link(RUN, 3)), refused);
        assert_eq!(EventScope::derive(&rejected(), &id, link(RUN, 3)), refused);
    }

    /// A coordinate names an exchange of THIS run that began before this event.
    #[test]
    fn a_coordinate_from_another_run_or_a_later_event_is_refused() {
        let id = EventId::new(RUN, 5);
        let signed = record(AuditSubject::response_signed());
        let refused = Err(EventIdentityFailure::ScopeRefused);
        let other = RunId::fixed([0x22; 16]);
        assert_eq!(EventScope::derive(&signed, &id, link(other, 3)), refused);
        assert_eq!(EventScope::derive(&signed, &id, link(RUN, 5)), refused);
        assert_eq!(EventScope::derive(&signed, &id, link(RUN, 6)), refused);
    }

    /// An intent belongs to the accepted exchange it names, and to nothing else: it has no
    /// scope without a coordinate of this run generated before it.
    #[test]
    fn an_intent_belongs_only_to_an_earlier_accepted_exchange_of_its_run() {
        let id = EventId::new(RUN, 5);
        let coordinate = |run, seq| ExchangeCoordinate::of_accepted(EventId::new(run, seq));
        assert_eq!(
            EventScope::of_intent(&id, coordinate(RUN, 3)),
            Ok(EventScope::Exchange(coordinate(RUN, 3)))
        );
        let refused = Err(EventIdentityFailure::ScopeRefused);
        let other = RunId::fixed([0x22; 16]);
        assert_eq!(EventScope::of_intent(&id, coordinate(other, 3)), refused);
        assert_eq!(EventScope::of_intent(&id, coordinate(RUN, 5)), refused);
        assert_eq!(EventScope::of_intent(&id, coordinate(RUN, 6)), refused);
    }

    #[test]
    fn a_coordinate_names_the_accepted_event() {
        let id = EventId::new(RUN, 4);
        assert_eq!(ExchangeCoordinate::of_accepted(id).accepted_event(), id);
    }
}
