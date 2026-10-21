// SPDX-License-Identifier: Apache-2.0
//! The identity of one audit event: its run, and its number within that run.

use super::RunId;

/// One event's identity, `(run, seq)`, allocated once when the event is produced.
///
/// There is no ordering between identities. Two events of one run compare by their `seq`,
/// which [`EventId::seq_within`] hands out only for the run asked about, and `seq` is the
/// GENERATION order of that run — not the order a transport delivered them in. Across runs
/// there is no order at all, which is why this type implements neither `PartialOrd` nor
/// `Ord`.
///
/// A transport's position for an event (a stream ID, an offset, a line number) is a
/// location and never this: a retried delivery is the same event at another location.
///
/// The only producer is the run's allocator, which hands out each `seq` once, so `seq` lies
/// in `0..i64::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventId {
    run: RunId,
    seq: i64,
}

impl EventId {
    /// The identity the allocator of `run` hands out as its `seq`-th.
    pub(super) fn new(run: RunId, seq: i64) -> Self {
        EventId { run, seq }
    }

    /// The run this event belongs to.
    pub fn run(&self) -> RunId {
        self.run
    }

    /// This event's number within `run`, or `None` when it belongs to another run: a `seq`
    /// from one run says nothing about order in another.
    pub fn seq_within(&self, run: &RunId) -> Option<i64> {
        (self.run == *run).then_some(self.seq)
    }

    /// Both coordinates, for the encoding and the scope check inside this subtree.
    pub(super) fn parts(&self) -> (RunId, i64) {
        (self.run, self.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_names_its_run_and_its_number_in_it() {
        let run = RunId::fixed([1; 16]);
        let id = EventId::new(run, 7);
        assert_eq!(id.run(), run);
        assert_eq!(id.seq_within(&run), Some(7));
        assert_eq!(id.parts(), (run, 7));
        assert_eq!(id.seq_within(&RunId::fixed([2; 16])), None);
    }
}
