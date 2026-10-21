// SPDX-License-Identifier: Apache-2.0
//! What an event's identity is bound to, and what a second sighting of it means.

use super::{ContentDigest, EventId};

/// An event's identity together with its content digest: the pair every sink and consumer
/// deduplicates on (ADR-MCPRE-070 §8).
///
/// It carries no transport position. Where a delivery landed is a location, and a retried
/// delivery of one event is the same binding at another location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventBinding {
    id: EventId,
    digest: ContentDigest,
}

/// What a second sighting of a binding is, when it is not a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recurrence {
    /// Another event: the identities differ.
    DistinctEvent,
    /// The same event again — same identity, same content — as a retry delivers it.
    IdenticalRetry,
}

/// One identity seen with two different contents. Never an update and never a newer
/// version: something reused an identity, and which content is the event cannot be decided
/// from the two sightings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityConflict {
    id: EventId,
    first: ContentDigest,
    second: ContentDigest,
}

impl EventBinding {
    /// The binding of the event `id` whose canonical bytes digest to `digest`.
    pub(super) fn new(id: EventId, digest: ContentDigest) -> Self {
        EventBinding { id, digest }
    }

    /// The event's identity.
    pub fn id(&self) -> EventId {
        self.id
    }

    /// The event's content digest.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// What `later` is, given that `self` was seen first.
    pub fn recurrence_of(&self, later: &EventBinding) -> Result<Recurrence, IntegrityConflict> {
        if self.id != later.id {
            return Ok(Recurrence::DistinctEvent);
        }
        if self.digest == later.digest {
            return Ok(Recurrence::IdenticalRetry);
        }
        Err(IntegrityConflict {
            id: self.id,
            first: self.digest,
            second: later.digest,
        })
    }
}

impl IntegrityConflict {
    /// The identity that was seen twice.
    pub fn id(&self) -> EventId {
        self.id
    }

    /// The content first seen under it.
    pub fn first(&self) -> ContentDigest {
        self.first
    }

    /// The other content seen under it.
    pub fn second(&self) -> ContentDigest {
        self.second
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_record::envelope::RunId;

    fn binding(seq: i64, content: &[u8]) -> EventBinding {
        EventBinding::new(
            EventId::new(RunId::fixed([3; 16]), seq),
            ContentDigest::of(content),
        )
    }

    #[test]
    fn a_binding_is_classified_against_an_earlier_sighting() {
        let first = binding(1, b"a");
        assert_eq!(
            first.recurrence_of(&binding(1, b"a")),
            Ok(Recurrence::IdenticalRetry)
        );
        assert_eq!(
            first.recurrence_of(&binding(2, b"a")),
            Ok(Recurrence::DistinctEvent)
        );
        assert_eq!(
            first.recurrence_of(&binding(2, b"b")),
            Ok(Recurrence::DistinctEvent)
        );
        let conflict = first
            .recurrence_of(&binding(1, b"b"))
            .expect_err("one identity, two contents");
        assert_eq!(conflict.id(), first.id());
        assert_eq!(conflict.first(), first.digest());
        assert_eq!(conflict.second(), ContentDigest::of(b"b"));
    }
}
