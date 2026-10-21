// SPDX-License-Identifier: Apache-2.0
//! The emission funnel: every decision the serving path records becomes an event here, and
//! is offered to the installed observer from here.
//!
//! Two steps, kept apart. PRODUCTION allocates the event's identity and fixes its bytes,
//! and happens for every decision whatever observer is installed. The OFFER hands the
//! produced event to the sink, contains the sink's faults, and is the only step that depends
//! on a sink being installed.

use super::envelope;
use super::{AuditEnvelope, AuditRecord, AuditSubject, EventIdentityFailure, ExchangeCoordinate};

/// Produce one record as an event, and offer it to the observer if one is installed.
///
/// The one place that turns a decision into an event, so no emitter carries its own copy of
/// either step. `subject` decides which authorities the record carries; the caller that
/// knows which half of the exchange it is reporting makes that choice, and the type refuses
/// the other combination.
///
/// Production does not depend on the observer: the event is numbered whether or not a sink
/// is installed, so the exchange coordinate an accepted request establishes is the same
/// under every observer configuration. Only the offer is conditional.
///
/// `exchange` is the coordinate a response belongs to — what this function returned for
/// the exchange's `request.accepted` — and `None` for a request. The return value is the
/// coordinate of the exchange the produced event belongs to, which is how an accepted
/// request hands it to the responses that follow.
pub(crate) fn record_to(
    audit: &crate::audit_sink::MaybeAuditSink,
    exchange: Option<ExchangeCoordinate>,
    subject: AuditSubject,
    actor_id: Option<String>,
    status: u16,
    now: i64,
) -> Option<ExchangeCoordinate> {
    let produced = produce(
        exchange,
        AuditRecord {
            subject,
            actor_id,
            status,
            at_unix: now,
        },
    );
    if let Some(sink) = audit.as_deref() {
        offer(sink, &produced);
    }
    produced.ok()?.exchange_coordinate()
}

/// Produce `record` as this process's next event: allocate its identity, derive its scope,
/// and fix its canonical bytes and digest. Nothing is offered to anyone.
///
/// Crate-visible because the outcome crossing (ADR-MCPRE-070 G2) commits a response event
/// BEFORE it is offered, so production and offer happen in two owners at two instants.
/// [`offer_produced`] is the other half; an event produced and never offered is a `seq` hole.
pub(crate) fn produce(
    exchange: Option<ExchangeCoordinate>,
    record: AuditRecord,
) -> Result<AuditEnvelope, EventIdentityFailure> {
    envelope::process_allocator()
        .and_then(|allocator| AuditEnvelope::produce(allocator, exchange, record))
}

/// Offer an event [`produce`] already numbered to the observer, if one is installed, with
/// the same fault containment as [`record_to`]: the committed outcome reaches the observer
/// as the SAME bytes the commitment authority holds.
pub(crate) fn offer_produced(audit: &crate::audit_sink::MaybeAuditSink, envelope: &AuditEnvelope) {
    if let Some(sink) = audit.as_deref() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink.record(envelope)));
    }
}

/// Offer a produced event, or the reason there is none, to `sink`.
///
/// `AuditSink` is a seam an embedder implements, and its contract is that a sink fault
/// MUST NOT fail the request. This is the one funnel every emitter passes through, so a
/// panicking sink costs one record (the panic hook has already reported it on stderr) rather
/// than unwinding into the connection task. AssertUnwindSafe holds: the closures only borrow
/// the sink and the envelope or failure, and no proxy state is read after an unwind.
fn offer(
    sink: &dyn crate::audit_sink::AuditSink,
    produced: &Result<AuditEnvelope, EventIdentityFailure>,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match produced {
        Ok(envelope) => sink.record(envelope),
        Err(failure) => sink.unnumbered(failure),
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_enforcer::AdmissionFacet;
    use crate::audit_record::{EventAllocator, Recurrence, RunId};

    struct PanickingSink;

    impl crate::audit_sink::AuditSink for PanickingSink {
        fn record(&self, _envelope: &AuditEnvelope) {
            panic!("sink fault");
        }

        fn unnumbered(&self, _failure: &EventIdentityFailure) {
            panic!("sink fault");
        }
    }

    #[test]
    fn a_panicking_sink_loses_the_record_and_does_not_unwind_into_the_request() {
        let audit: crate::audit_sink::MaybeAuditSink = Some(std::sync::Arc::new(PanickingSink));
        let accepted = AuditSubject::request_accepted(
            &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
            AdmissionFacet::NotConfigured,
        );
        let exchange = record_to(&audit, None, accepted, None, 200, 1);
        assert!(
            exchange.is_some(),
            "the event was produced before the sink faulted"
        );
        record_to(
            &audit,
            exchange,
            AuditSubject::response_signed(),
            None,
            200,
            1,
        );
        record_to(&audit, None, AuditSubject::response_signed(), None, 200, 1);
    }

    /// A sink that delivers every event three times, as a transport retrying after a fault
    /// would.
    struct RetryingSink(std::sync::Arc<crate::audit_sink::CollectingAuditSink>);

    impl crate::audit_sink::AuditSink for RetryingSink {
        fn record(&self, envelope: &AuditEnvelope) {
            for _ in 0..3 {
                self.0.record(envelope);
            }
        }

        fn unnumbered(&self, failure: &EventIdentityFailure) {
            self.0.unnumbered(failure);
        }
    }

    fn accepted_record() -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::request_accepted(
                &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                AdmissionFacet::NotConfigured,
            ),
            actor_id: Some("actor-a".to_owned()),
            status: 200,
            at_unix: 1,
        }
    }

    fn signed_record() -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::response_signed(),
            actor_id: Some("actor-a".to_owned()),
            status: 200,
            at_unix: 2,
        }
    }

    /// Identity is allocated once per PRODUCTION, never per delivery attempt: three
    /// deliveries carry one identity and one set of bytes, and they consume no numbers.
    #[test]
    fn a_retrying_sink_sees_one_identity_for_all_attempts() {
        let inner = std::sync::Arc::new(crate::audit_sink::CollectingAuditSink::new());
        let sink = RetryingSink(inner.clone());
        let run = RunId::fixed([0x42; 16]);
        let allocator = EventAllocator::starting_at(run, 0);
        let accepted = AuditEnvelope::produce(&allocator, None, accepted_record());
        offer(&sink, &accepted);
        let exchange = accepted.ok().and_then(|e| e.exchange_coordinate());
        offer(
            &sink,
            &AuditEnvelope::produce(&allocator, exchange, signed_record()),
        );
        let delivered = inner.envelopes();
        assert_eq!(delivered.len(), 6, "two events, three attempts each");
        for (event, attempts) in [(0, &delivered[..3]), (1, &delivered[3..])] {
            for attempt in attempts {
                assert_eq!(attempt.id().seq_within(&run), Some(event));
                assert_eq!(attempt.canonical_bytes(), attempts[0].canonical_bytes());
                assert_eq!(
                    attempts[0].binding().recurrence_of(&attempt.binding()),
                    Ok(Recurrence::IdenticalRetry)
                );
            }
        }
        assert!(inner.unnumbered_failures().is_empty());
    }

    /// An exhausted run produces nothing: the sink is told why, receives no event, and no
    /// exchange coordinate is handed on for a response to borrow.
    #[test]
    fn exhaustion_reaches_the_sink_as_unnumbered_and_emits_nothing() {
        let sink = crate::audit_sink::CollectingAuditSink::new();
        let run = RunId::fixed([0x43; 16]);
        let exhausted = EventAllocator::starting_at(run, i64::MAX);
        let accepted = AuditEnvelope::produce(&exhausted, None, accepted_record());
        offer(&sink, &accepted);
        let exchange = accepted.ok().and_then(|e| e.exchange_coordinate());
        assert_eq!(exchange, None);
        let fresh = EventAllocator::starting_at(run, 0);
        offer(
            &sink,
            &AuditEnvelope::produce(&fresh, exchange, signed_record()),
        );
        assert!(
            sink.envelopes().is_empty(),
            "nothing unnumbered reaches a sink as an event"
        );
        assert_eq!(
            sink.unnumbered_failures(),
            [
                EventIdentityFailure::SequenceExhausted { run },
                EventIdentityFailure::ScopeRefused,
            ]
        );
    }

    /// The exchange coordinate does not depend on whether anyone observes: with no sink
    /// installed an accepted request is still produced as an event, and a response of its
    /// exchange is still produced under its coordinate.
    #[test]
    fn the_exchange_coordinate_does_not_depend_on_an_observer() {
        let accepted = accepted_record();
        let exchange = record_to(
            &None,
            None,
            accepted.subject,
            accepted.actor_id,
            accepted.status,
            accepted.at_unix,
        )
        .expect("an accepted request opens an exchange with no observer installed");
        let signed = signed_record();
        assert_eq!(
            record_to(
                &None,
                Some(exchange),
                signed.subject,
                signed.actor_id,
                signed.status,
                signed.at_unix,
            ),
            Some(exchange),
            "the response is produced in the accepted request's exchange"
        );
    }
}
