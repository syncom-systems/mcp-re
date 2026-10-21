// SPDX-License-Identifier: Apache-2.0
//! The audit envelope: one produced event, with its identity and its canonical content
//! (ADR-MCPRE-070 §8, D5, D9).
//!
//! # What this owns
//!
//! An event is given its identity `(run, seq)` ONCE, when it is produced, and its canonical
//! bytes and digest at the same moment. Everything after that — a sink, a queue, a retry —
//! hands the same envelope on and allocates nothing, so a transport that retries delivers
//! one identity and one set of bytes however many attempts it makes.
//!
//! ```text
//! produce:  allocate (run, seq) ──> derive scope ──> encode ──> digest ──> AuditEnvelope
//! offer:                                     AuditSink::record(&envelope), if a sink is installed
//! ```
//!
//! Production and offering are separate steps. Production happens for every decision
//! whether or not an observer is installed, so an exchange's coordinate is the same under
//! every observer configuration; offering is the observer's step alone.
//!
//! # Two orders, and no third
//!
//! `seq` is the GENERATION order of one run. The order a transport delivers events in is
//! ARRIVAL order, a fact about that transport, and the two differ when producers on several
//! cores hand off concurrently. Across runs there is no order at all: `run` is a random
//! 128-bit value, and nothing compares one run's `seq` with another's.
//!
//! # What holding an envelope does not mean
//!
//! An envelope proves this process produced the event and numbered it. It is not evidence
//! that any sink kept it: possession is not commitment, an envelope is not a witness of
//! delivery, and nothing here is durable. A record that reached no sink still took its
//! number, so its absence is a hole in its run rather than a silent gap.

mod allocator;
mod binding;
mod canonical;
mod digest;
mod event;
mod event_id;
mod identity_failure;
mod run_id;
mod scope;

pub(crate) use allocator::open_process_run;
#[cfg(test)]
pub(crate) use allocator::EventAllocator;
pub use binding::{EventBinding, IntegrityConflict, Recurrence};
pub use canonical::CANONICAL_VERSION;
pub use digest::ContentDigest;
pub use event::CanonicalEvent;
pub use event_id::EventId;
pub use identity_failure::EventIdentityFailure;
pub use run_id::RunId;
pub use scope::{EventScope, ExchangeCoordinate};

use crate::audit_record::AuditRecord;

/// One produced audit event of a decision: its [`CanonicalEvent`] and the record it encodes.
///
/// The fields are private and the only constructor is [`AuditEnvelope::produce`], so every
/// envelope's event was produced from exactly the record it carries, and its scope was
/// derived from that record rather than supplied.
#[derive(Debug, Clone)]
pub struct AuditEnvelope {
    event: CanonicalEvent,
    record: AuditRecord,
}

impl AuditEnvelope {
    /// Produce the event `record` from `allocator`, in the exchange `link` names when it is a
    /// response.
    pub(in crate::audit_record) fn produce(
        allocator: &allocator::EventAllocator,
        link: Option<ExchangeCoordinate>,
        record: AuditRecord,
    ) -> Result<AuditEnvelope, EventIdentityFailure> {
        let event = CanonicalEvent::produce(
            allocator,
            |id| EventScope::derive(&record, id, link),
            &record.audit_fields(),
        )?;
        Ok(AuditEnvelope { event, record })
    }

    /// [`AuditEnvelope::produce`] for a test outside this subtree that needs envelopes
    /// numbered from a known point. Every identity still comes from `allocator`.
    #[cfg(test)]
    pub(crate) fn produce_for_test(
        allocator: &EventAllocator,
        link: Option<ExchangeCoordinate>,
        record: AuditRecord,
    ) -> Result<AuditEnvelope, EventIdentityFailure> {
        Self::produce(allocator, link, record)
    }

    /// The produced event: what a commitment authority is asked to commit.
    pub fn event(&self) -> &CanonicalEvent {
        &self.event
    }

    /// The event's identity.
    pub fn id(&self) -> EventId {
        self.event.id()
    }

    /// Which exchange the event belongs to.
    pub fn scope(&self) -> EventScope {
        self.event.scope()
    }

    /// The coordinate of the exchange this event belongs to; see
    /// [`CanonicalEvent::exchange_coordinate`].
    pub fn exchange_coordinate(&self) -> Option<ExchangeCoordinate> {
        self.event.exchange_coordinate()
    }

    /// The record, exactly as it was produced.
    pub fn record(&self) -> &AuditRecord {
        &self.record
    }

    /// The canonical v[`CANONICAL_VERSION`] bytes, fixed at production.
    pub fn canonical_bytes(&self) -> &[u8] {
        self.event.canonical_bytes()
    }

    /// The digest of [`AuditEnvelope::canonical_bytes`].
    pub fn digest(&self) -> ContentDigest {
        self.event.digest()
    }

    /// The identity and digest a consumer deduplicates on.
    pub fn binding(&self) -> EventBinding {
        self.event.binding()
    }
}

/// The allocator every event this process produces is numbered by.
pub(in crate::audit_record) fn process_allocator(
) -> Result<&'static allocator::EventAllocator, EventIdentityFailure> {
    allocator::process()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_enforcer::AdmissionFacet;
    use crate::audit_record::AuditSubject;
    use crate::authorization::{
        AuthorizationFacet, AuthorizationPosture, AuthorizationRefusalFacet,
    };

    const RUN: RunId = RunId::fixed([0x5a; 16]);

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

    fn signed() -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::response_signed(),
            actor_id: Some("actor-a".into()),
            status: 200,
            at_unix: 11,
        }
    }

    /// A retry hands the same envelope on: one identity, one set of bytes, one digest.
    #[test]
    fn an_identical_retry_keeps_id_bytes_and_digest() {
        let allocator = EventAllocator::starting_at(RUN, 0);
        let first =
            AuditEnvelope::produce(&allocator, None, accepted("actor-a")).expect("produced");
        let retried = first.clone();
        assert_eq!(retried.id(), first.id());
        assert_eq!(retried.canonical_bytes(), first.canonical_bytes());
        assert_eq!(
            first.binding().recurrence_of(&retried.binding()),
            Ok(Recurrence::IdenticalRetry)
        );
    }

    /// The reused-run hazard: two allocators on one run hand out one identity for two
    /// different records, and the bindings say so instead of one overwriting the other.
    #[test]
    fn same_id_with_other_content_is_an_integrity_conflict() {
        let (one, two) = (
            EventAllocator::starting_at(RUN, 0),
            EventAllocator::starting_at(RUN, 0),
        );
        let a = AuditEnvelope::produce(&one, None, accepted("actor-a")).expect("produced");
        let b = AuditEnvelope::produce(&two, None, accepted("actor-b")).expect("produced");
        assert_eq!(a.id(), b.id(), "one run, one seq");
        let conflict = a
            .binding()
            .recurrence_of(&b.binding())
            .expect_err("one identity, two contents");
        assert_eq!(
            (conflict.id(), conflict.first(), conflict.second()),
            (a.id(), a.digest(), b.digest())
        );
    }

    #[test]
    fn distinct_ids_are_distinct_events() {
        let allocator = EventAllocator::starting_at(RUN, 0);
        let a = AuditEnvelope::produce(&allocator, None, accepted("actor-a")).expect("produced");
        let b = AuditEnvelope::produce(&allocator, None, accepted("actor-a")).expect("produced");
        assert_ne!(a.id(), b.id());
        assert_eq!(
            a.binding().recurrence_of(&b.binding()),
            Ok(Recurrence::DistinctEvent)
        );
    }

    /// Delivery order is not identity: the same two events delivered in either order are
    /// the same two bindings.
    #[test]
    fn arrival_order_does_not_enter_identity() {
        let allocator = EventAllocator::starting_at(RUN, 0);
        let a = AuditEnvelope::produce(&allocator, None, accepted("actor-a")).expect("produced");
        let b = AuditEnvelope::produce(&allocator, a.exchange_coordinate(), signed())
            .expect("produced");
        let (forward, reverse) = (
            crate::audit_sink::CollectingAuditSink::new(),
            crate::audit_sink::CollectingAuditSink::new(),
        );
        use crate::audit_sink::AuditSink;
        forward.record(&a);
        forward.record(&b);
        reverse.record(&b);
        reverse.record(&a);
        let bindings = |sink: &crate::audit_sink::CollectingAuditSink| {
            let mut all: Vec<_> = sink
                .envelopes()
                .iter()
                .map(|e| (e.id().seq_within(&RUN), e.binding()))
                .collect();
            all.sort_by_key(|(seq, _)| *seq);
            all
        };
        assert_eq!(bindings(&forward), bindings(&reverse));
        assert_ne!(
            forward.envelopes()[0].id(),
            reverse.envelopes()[0].id(),
            "arrival differs"
        );
    }

    #[test]
    fn an_origin_envelope_is_its_own_exchange_coordinate() {
        let allocator = EventAllocator::starting_at(RUN, 0);
        let origin =
            AuditEnvelope::produce(&allocator, None, accepted("actor-a")).expect("produced");
        assert_eq!(origin.scope(), EventScope::Origin);
        let coordinate = origin
            .exchange_coordinate()
            .expect("an accepted request opens an exchange");
        assert_eq!(coordinate.accepted_event(), origin.id());
        let response =
            AuditEnvelope::produce(&allocator, Some(coordinate), signed()).expect("produced");
        assert_eq!(response.scope(), EventScope::Exchange(coordinate));
        assert_eq!(response.exchange_coordinate(), Some(coordinate));
        let refused = AuditEnvelope::produce(
            &allocator,
            None,
            AuditRecord {
                subject: AuditSubject::request_rejected(
                    Some(&mcp_re_core::McpReError::ReplayDetected),
                    AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
                    AdmissionFacet::NotReached,
                ),
                actor_id: None,
                status: 409,
                at_unix: 12,
            },
        )
        .expect("produced");
        assert_eq!(refused.scope(), EventScope::PreAcceptance);
        assert_eq!(refused.exchange_coordinate(), None);
    }

    /// The envelope carries the record it was given, and its bytes are that record's.
    #[test]
    fn the_record_rides_unchanged() {
        let allocator = EventAllocator::starting_at(RUN, 0);
        let record = accepted("did:example:agent-1");
        let envelope = AuditEnvelope::produce(&allocator, None, record.clone()).expect("produced");
        assert_eq!(envelope.record(), &record);
        assert_eq!(
            envelope.record().actor_id.as_deref(),
            Some("did:example:agent-1")
        );
        assert_eq!(
            envelope.record().subject.authorization(),
            record.subject.authorization()
        );
        assert_eq!(
            envelope.record().subject.admission(),
            Some(AdmissionFacet::LiveConfirmed)
        );
        let expected =
            canonical::encode(&envelope.id(), &EventScope::Origin, &record.audit_fields())
                .expect("encodes");
        assert_eq!(envelope.canonical_bytes(), &expected[..]);
        assert_eq!(envelope.digest(), ContentDigest::of(&expected));
        assert_eq!(envelope.canonical_bytes()[0], CANONICAL_VERSION);
    }
}
