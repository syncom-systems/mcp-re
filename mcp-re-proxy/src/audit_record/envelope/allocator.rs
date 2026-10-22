// SPDX-License-Identifier: Apache-2.0
//! The allocator of one run's event identities, and this process's run.
//!
//! An identity is allocated when an event is PRODUCED — once — and never by whatever
//! delivers it, so a transport that retries delivers one identity however many attempts it
//! makes. Allocation precedes the hand-off to any sink, so a record a sink never received
//! still took its number and leaves a hole in its run.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::OnceLock;

use super::{EventId, EventIdentityFailure, RunId};

/// The allocator of one run's identities, numbering from `seq = 0`.
#[derive(Debug)]
pub(crate) struct EventAllocator {
    run: RunId,
    next: AtomicI64,
}

impl EventAllocator {
    /// A run's allocator, starting at `seq = 0`.
    fn starting(run: RunId) -> Self {
        EventAllocator {
            run,
            next: AtomicI64::new(0),
        }
    }

    /// A run's allocator whose next `seq` is `next`.
    ///
    /// A test-only producer of allocator STATE, never of an identity: every [`EventId`] it
    /// yields still comes from [`EventAllocator::next`], so the edge of the sequence can be
    /// reached without allocating `i64::MAX` identities first.
    #[cfg(test)]
    pub(crate) fn starting_at(run: RunId, next: i64) -> Self {
        EventAllocator {
            run,
            next: AtomicI64::new(next),
        }
    }

    /// The run this allocator numbers.
    pub(crate) fn run(&self) -> RunId {
        self.run
    }

    /// The next identity of this run, or why there is none.
    ///
    /// The step is one compare-and-swap with checked arithmetic, so no two callers receive
    /// one `seq` and the counter never wraps. The last `seq` handed out is `i64::MAX - 1`:
    /// the counter then holds `i64::MAX`, has no successor, and every later call fails with
    /// [`EventIdentityFailure::SequenceExhausted`], permanently.
    pub(in crate::audit_record) fn next(&self) -> Result<EventId, EventIdentityFailure> {
        self.next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map(|seq| EventId::new(self.run, seq))
            .map_err(|_| EventIdentityFailure::SequenceExhausted { run: self.run })
    }
}

/// This process's run: one allocator, drawn once.
static PROCESS_RUN: OnceLock<EventAllocator> = OnceLock::new();

/// This process's run, drawing it on first use. `None` when the OS CSPRNG fails; a later
/// call draws again.
pub(crate) fn open_process_run() -> Option<RunId> {
    open_drawing(&PROCESS_RUN, RunId::draw).map(EventAllocator::run)
}

/// The allocator in `cell`, drawing its run with `draw` on first use. There is no other run
/// to fall back to: a failed draw leaves `cell` empty and opens nothing.
fn open_drawing(
    cell: &'static OnceLock<EventAllocator>,
    draw: fn() -> Option<RunId>,
) -> Option<&'static EventAllocator> {
    if let Some(allocator) = cell.get() {
        return Some(allocator);
    }
    let drawn = EventAllocator::starting(draw()?);
    Some(cell.get_or_init(|| drawn))
}

/// The allocator every produced event of this process is numbered by.
pub(in crate::audit_record) fn process() -> Result<&'static EventAllocator, EventIdentityFailure> {
    open_drawing(&PROCESS_RUN, RunId::draw).ok_or(EventIdentityFailure::RunUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> RunId {
        RunId::draw().expect("the OS CSPRNG yields a run")
    }

    #[test]
    fn each_record_of_a_run_takes_the_next_number() {
        let allocator = EventAllocator::starting(run());
        let first = allocator.next().expect("a fresh run numbers");
        let second = allocator.next().expect("a fresh run numbers");
        assert_eq!(first.seq_within(&allocator.run), Some(0));
        assert_eq!(second.seq_within(&allocator.run), Some(1));
    }

    /// A restart: two runs number their records from 0, and the run is what tells their
    /// equal numbers apart.
    #[test]
    fn two_runs_with_the_same_numbers_stay_distinguishable() {
        let (before, after) = (
            EventAllocator::starting(run()),
            EventAllocator::starting(run()),
        );
        let (a, b) = (
            before.next().expect("a fresh run numbers"),
            after.next().expect("a fresh run numbers"),
        );
        assert_ne!(a.run(), b.run(), "two draws name two runs");
        assert_ne!(a, b, "equal seq in different runs is not the same identity");
        assert_eq!(a.seq_within(&a.run()), b.seq_within(&b.run()));
    }

    #[test]
    fn a_position_has_no_number_in_another_run() {
        let (mine, other) = (EventAllocator::starting(run()), run());
        let id = mine.next().expect("a fresh run numbers");
        assert_eq!(id.seq_within(&other), None);
        assert_eq!(id.seq_within(&id.run()), Some(0));
    }

    /// A CSPRNG failure opens no run and leaves none behind to number records under; the
    /// next successful draw opens it.
    #[test]
    fn a_failed_draw_opens_nothing() {
        let cell = Box::leak(Box::new(OnceLock::new()));
        assert!(open_drawing(cell, || None).is_none());
        assert!(cell.get().is_none(), "a failed draw must not leave a run");
        let opened = open_drawing(cell, RunId::draw).expect("the OS CSPRNG yields a run");
        assert!(std::ptr::eq(
            opened,
            cell.get().expect("the draw filled the cell")
        ));
    }

    #[test]
    fn the_process_stream_is_drawn_once() {
        let first = open_process_run().expect("the OS CSPRNG yields a run");
        assert_eq!(
            open_process_run(),
            Some(first),
            "a second call must not draw a second run"
        );
        let allocator = process().expect("an opened run numbers");
        assert_eq!(allocator.run(), first);
    }

    /// The sequence ends; it does not wrap. The last two numbers are handed out, and then
    /// every call fails for good, with no `seq` ever handed out twice or below one already
    /// issued.
    #[test]
    fn exhaustion_is_permanent_and_never_wraps() {
        let run = RunId::fixed([7; 16]);
        let allocator = EventAllocator::starting_at(run, i64::MAX - 2);
        let issued: Vec<i64> = (0..2)
            .map(|_| {
                let id = allocator
                    .next()
                    .expect("below the edge, a number is issued");
                id.seq_within(&run).expect("the allocator's own run")
            })
            .collect();
        assert_eq!(issued, [i64::MAX - 2, i64::MAX - 1]);
        for _ in 0..3 {
            assert_eq!(
                allocator.next(),
                Err(EventIdentityFailure::SequenceExhausted { run })
            );
        }
    }

    /// No two concurrent producers receive one identity, and none is skipped.
    #[test]
    fn concurrent_allocation_hands_out_each_seq_once() {
        const THREADS: usize = 8;
        const EACH: usize = 10_000;
        let allocator = EventAllocator::starting(run());
        let start = std::sync::Barrier::new(THREADS);
        let mut seqs: Vec<i64> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        (0..EACH)
                            .map(|_| {
                                let id = allocator.next().expect("far from the edge");
                                id.seq_within(&allocator.run).expect("its own run")
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("an allocating thread completes"))
                .collect()
        });
        seqs.sort_unstable();
        let expected: Vec<i64> = (0..i64::try_from(THREADS * EACH).expect("small")).collect();
        assert_eq!(seqs, expected, "every seq exactly once, none skipped");
    }

    /// The edge under contention: exactly the remaining numbers are issued, each once, and
    /// every other caller is told the run is exhausted.
    #[test]
    fn the_last_seqs_are_contended_without_reuse() {
        const THREADS: usize = 8;
        const REMAINING: i64 = 5;
        for _ in 0..200 {
            let run = RunId::fixed([9; 16]);
            let allocator = EventAllocator::starting_at(run, i64::MAX - REMAINING);
            let start = std::sync::Barrier::new(THREADS);
            let outcomes: Vec<Result<EventId, EventIdentityFailure>> =
                std::thread::scope(|scope| {
                    let handles: Vec<_> = (0..THREADS)
                        .map(|_| {
                            scope.spawn(|| {
                                start.wait();
                                (0..2).map(|_| allocator.next()).collect::<Vec<_>>()
                            })
                        })
                        .collect();
                    handles
                        .into_iter()
                        .flat_map(|h| h.join().expect("an allocating thread completes"))
                        .collect()
                });
            let mut issued: Vec<i64> = outcomes
                .iter()
                .filter_map(|o| o.ok().and_then(|id| id.seq_within(&run)))
                .collect();
            issued.sort_unstable();
            assert_eq!(
                issued,
                ((i64::MAX - REMAINING)..i64::MAX).collect::<Vec<_>>()
            );
            let refused = outcomes
                .iter()
                .filter(|o| **o == Err(EventIdentityFailure::SequenceExhausted { run }))
                .count();
            assert_eq!(refused, THREADS * 2 - 5);
        }
    }
}
