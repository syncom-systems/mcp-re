// SPDX-License-Identifier: Apache-2.0
//! The execution-intent fact (ADR-MCPRE-070 D1, G1).
//!
//! What a deployment under the required audit posture commits before an admitted exchange
//! is dispatched: *this exchange is about to be sent to the backend*. A fact of its own, and
//! not `request.accepted` — admitted is not executed, and five refusals lie between the two.
//!
//! # Not an [`AuditRecord`](super::AuditRecord), and never observed
//!
//! An intent is produced as a [`CanonicalEvent`] and handed to the commitment authority. It
//! is never wrapped in an [`super::AuditEnvelope`], so it cannot reach an
//! [`AuditSink`](crate::audit_sink::AuditSink): the best-effort stream emits no intent line
//! and keeps its v0.18.1 contract (D1). It has no `decision`, because no Core decision is
//! taken here, no `reason`, because it is not a verdict, and no `status`, because nothing has
//! been answered yet — a status would be a fabricated value.

use mcp_re_core::audit::event_type;

use super::envelope::{process_allocator, CanonicalEvent, EventScope};
use super::text::AuditField;
use super::{EventIdentityFailure, ExchangeCoordinate};

/// The intent to dispatch one admitted exchange: who it is for, and when it was decided.
///
/// The exchange itself is not a field. It is the event's scope — the coordinate of the
/// exchange's `request.accepted` (D9) — so no raw request digest is carried, and an intent
/// cannot be produced for no exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecutionIntent<'a> {
    actor_id: &'a str,
    at_unix: i64,
}

impl<'a> ExecutionIntent<'a> {
    /// The intent for `actor_id`'s exchange, at the exchange's own clock reading.
    pub(crate) fn new(actor_id: &'a str, at_unix: i64) -> Self {
        ExecutionIntent { actor_id, at_unix }
    }

    /// The intent's fields, each classified by its owner: three, in this order. Its own
    /// arm of the canonical schema (`canonical.rs`).
    pub(in crate::audit_record) fn audit_fields(&self) -> [AuditField<'a>; 3] {
        [
            AuditField::token("event", event_type::EXECUTION_INTENT),
            AuditField::text("actor", self.actor_id),
            AuditField::number("at", self.at_unix),
        ]
    }

    /// Produce this intent as the process's next event, in the exchange `coordinate` names.
    ///
    /// Numbered by the same allocator as every observed event, so its identity is unique in
    /// the run. Nothing is offered to the observer.
    pub(crate) fn produce(
        &self,
        coordinate: ExchangeCoordinate,
    ) -> Result<CanonicalEvent, EventIdentityFailure> {
        process_allocator().and_then(|allocator| {
            CanonicalEvent::produce(
                allocator,
                |id| EventScope::of_intent(id, coordinate),
                &self.audit_fields(),
            )
        })
    }

    /// [`ExecutionIntent::produce`] from a test's own allocator.
    #[cfg(test)]
    pub(crate) fn produce_for_test(
        &self,
        allocator: &super::EventAllocator,
        coordinate: ExchangeCoordinate,
    ) -> Result<CanonicalEvent, EventIdentityFailure> {
        CanonicalEvent::produce(
            allocator,
            |id| EventScope::of_intent(id, coordinate),
            &self.audit_fields(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_record::text::AuditValue;
    use crate::audit_record::{AuditEnvelope, AuditRecord, AuditSubject, EventAllocator, RunId};

    const RUN: RunId = RunId::fixed([0x1e; 16]);

    fn accepted(allocator: &EventAllocator) -> AuditEnvelope {
        AuditEnvelope::produce_for_test(
            allocator,
            None,
            AuditRecord {
                subject: AuditSubject::request_accepted(
                    &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                    crate::admission_enforcer::AdmissionFacet::NotConfigured,
                ),
                actor_id: Some("actor-a".into()),
                status: 200,
                at_unix: 10,
            },
        )
        .expect("produced")
    }

    #[test]
    fn an_intent_encodes_exactly_its_three_fields() {
        let fields = ExecutionIntent::new("actor-a", 10).audit_fields();
        let shape: Vec<_> = fields.iter().map(|f| (f.name, f.value.clone())).collect();
        assert_eq!(
            shape,
            [
                ("event", AuditValue::Token("mcp-re.execution.intent")),
                ("actor", AuditValue::Text("actor-a".into())),
                ("at", AuditValue::Number(10)),
            ]
        );
    }

    /// The intent names the exchange its accepted event opened, and nothing else (D9).
    #[test]
    fn an_intent_needs_an_exchange_link() {
        let allocator = EventAllocator::starting_at(RUN, 0);
        let origin = accepted(&allocator);
        let coordinate = origin
            .exchange_coordinate()
            .expect("an accepted event opens one");
        let intent = ExecutionIntent::new("actor-a", 10)
            .produce_for_test(&allocator, coordinate)
            .expect("produced");
        assert_eq!(intent.scope(), EventScope::Exchange(coordinate));
        assert_eq!(intent.exchange_coordinate(), Some(coordinate));
        assert_ne!(
            intent.id(),
            origin.id(),
            "its own identity, numbered after the origin"
        );

        // A coordinate from a later event, or from another run, names no exchange this
        // intent can belong to.
        let later = EventAllocator::starting_at(RUN, 9);
        let ahead = accepted(&later).exchange_coordinate().expect("opens one");
        assert_eq!(
            ExecutionIntent::new("actor-a", 10)
                .produce_for_test(&EventAllocator::starting_at(RUN, 3), ahead)
                .map(|e| e.id()),
            Err(EventIdentityFailure::ScopeRefused)
        );
        let elsewhere = accepted(&EventAllocator::starting_at(RunId::fixed([0x2e; 16]), 0))
            .exchange_coordinate()
            .expect("opens one");
        assert_eq!(
            ExecutionIntent::new("actor-a", 10)
                .produce_for_test(&allocator, elsewhere)
                .map(|e| e.id()),
            Err(EventIdentityFailure::ScopeRefused)
        );
    }

    /// One intent produced twice is two events: the identity is allocated at production,
    /// and the bytes differ by exactly that identity.
    #[test]
    fn each_production_is_a_new_event_of_the_run() {
        let allocator = EventAllocator::starting_at(RUN, 0);
        let coordinate = accepted(&allocator)
            .exchange_coordinate()
            .expect("opens one");
        let intent = ExecutionIntent::new("actor-a", 10);
        let (a, b) = (
            intent
                .produce_for_test(&allocator, coordinate)
                .expect("produced"),
            intent
                .produce_for_test(&allocator, coordinate)
                .expect("produced"),
        );
        assert_ne!(a.id(), b.id());
        assert_ne!(a.digest(), b.digest());
    }
}
