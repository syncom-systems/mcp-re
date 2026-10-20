// SPDX-License-Identifier: Apache-2.0
//! One produced event's identity, scope and canonical content (ADR-MCPRE-070 §8, D5).
//!
//! The part of an event a commitment authority is asked to commit, and all it needs: the
//! identity it deduplicates on, and the bytes it stores. Kept apart from what the event is
//! ABOUT, because two kinds of fact are produced as events and only one of them is offered to
//! the observer — an [`super::AuditEnvelope`] carries a decision's record, and an execution
//! intent ([`crate::audit_record::ExecutionIntent`]) is committed and never observed (D1).

use super::canonical;
use super::{allocator::EventAllocator, ExchangeCoordinate};
use super::{ContentDigest, EventBinding, EventId, EventIdentityFailure, EventScope};
use crate::audit_record::text::AuditField;

/// One event's identity, scope, canonical bytes and their digest, all fixed at production.
///
/// The fields are private and the only constructor is [`CanonicalEvent::produce`], so every
/// identity came from its run's allocator, its scope was derived from the event rather than
/// supplied, and its bytes and digest are the encoding of exactly the fields it was produced
/// from.
#[derive(Debug, Clone)]
pub struct CanonicalEvent {
    id: EventId,
    scope: EventScope,
    canonical: Box<[u8]>,
    digest: ContentDigest,
}

impl CanonicalEvent {
    /// Produce the next event of `allocator`'s run carrying `fields`, in the scope `scope_of`
    /// derives for the identity it was given.
    ///
    /// The identity is allocated first, so an event refused afterwards still leaves a hole
    /// in its run rather than vanishing without a number.
    pub(in crate::audit_record) fn produce(
        allocator: &EventAllocator,
        scope_of: impl FnOnce(&EventId) -> Result<EventScope, EventIdentityFailure>,
        fields: &[AuditField<'_>],
    ) -> Result<CanonicalEvent, EventIdentityFailure> {
        let id = allocator.next()?;
        let scope = scope_of(&id)?;
        let canonical = canonical::encode(&id, &scope, fields)?;
        let digest = ContentDigest::of(&canonical);
        Ok(CanonicalEvent {
            id,
            scope,
            canonical: canonical.into_boxed_slice(),
            digest,
        })
    }

    /// The event's identity.
    pub fn id(&self) -> EventId {
        self.id
    }

    /// Which exchange the event belongs to.
    pub fn scope(&self) -> EventScope {
        self.scope
    }

    /// The coordinate of the exchange this event belongs to: its own identity for an
    /// accepted request, the accepted event's for every later event of the exchange, and
    /// `None` for a request refused before any exchange was accepted and for an event about
    /// the run as a whole.
    pub fn exchange_coordinate(&self) -> Option<ExchangeCoordinate> {
        match self.scope {
            EventScope::Origin => Some(ExchangeCoordinate::of_accepted(self.id)),
            EventScope::Exchange(coordinate) => Some(coordinate),
            EventScope::PreAcceptance | EventScope::Run => None,
        }
    }

    /// The canonical v[`super::CANONICAL_VERSION`] bytes, fixed at production.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// The digest of [`CanonicalEvent::canonical_bytes`].
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// The identity and digest a consumer deduplicates on.
    pub fn binding(&self) -> EventBinding {
        EventBinding::new(self.id, self.digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_record::envelope::RunId;

    const RUN: RunId = RunId::fixed([0x6e; 16]);

    fn fields() -> Vec<AuditField<'static>> {
        vec![AuditField::token("event", "mcp-re.request.accepted")]
    }

    /// The scope is derived from the identity the allocator handed out, and a refused scope
    /// still consumed that identity.
    #[test]
    fn the_scope_is_derived_from_the_allocated_identity_and_a_refusal_keeps_its_hole() {
        let allocator = EventAllocator::starting_at(RUN, 4);
        let refused = CanonicalEvent::produce(
            &allocator,
            |_| Err(EventIdentityFailure::ScopeRefused),
            &fields(),
        );
        assert!(matches!(refused, Err(EventIdentityFailure::ScopeRefused)));
        let mut seen = None;
        let event = CanonicalEvent::produce(
            &allocator,
            |id| {
                seen = Some(*id);
                Ok(EventScope::Origin)
            },
            &fields(),
        )
        .expect("produced");
        assert_eq!(Some(event.id()), seen);
        assert_eq!(
            event.id().seq_within(&RUN),
            Some(5),
            "seq 4 was spent by the refusal"
        );
    }

    /// The bytes are the encoding of exactly the fields given, and the digest is theirs.
    #[test]
    fn the_bytes_and_digest_are_the_encoding_of_the_fields() {
        let event = CanonicalEvent::produce(
            &EventAllocator::starting_at(RUN, 0),
            |_| Ok(EventScope::Origin),
            &fields(),
        )
        .expect("produced");
        let expected =
            canonical::encode(&event.id(), &EventScope::Origin, &fields()).expect("encodes");
        assert_eq!(event.canonical_bytes(), &expected[..]);
        assert_eq!(event.digest(), ContentDigest::of(&expected));
        assert_eq!(event.binding().id(), event.id());
        assert_eq!(event.binding().digest(), event.digest());
        assert_eq!(
            event.exchange_coordinate().map(|c| c.accepted_event()),
            Some(event.id())
        );
    }
}
