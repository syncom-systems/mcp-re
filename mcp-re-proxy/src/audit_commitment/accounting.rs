// SPDX-License-Identifier: Apache-2.0
//! The commitment path's own accounting: what it was asked, what it answered, and what its
//! budget holds (ADR-MCPRE-070 §7.4, D2).

use std::sync::atomic::{AtomicU64, Ordering};

use crate::audit_record::AccountingCounts;

use super::budget::CommitmentBudget;
use super::{CommitmentFailure, ProviderId};

/// One established provider's counters and budget, shared with the run's entry point so the
/// shutdown report can be printed after the provider itself is reclaimed.
///
/// Counted per attempt, at the owner: a provider's claims are not counts. Every counter only
/// grows (`fetch_add`, wrapping only past `u64::MAX`, which no process reaches); the record and
/// the report state what this process observed, never more.
#[derive(Debug)]
pub(crate) struct CommitmentAccounting {
    provider: ProviderId,
    budget: CommitmentBudget,
    committed: AtomicU64,
    rejected: AtomicU64,
    unavailable: AtomicU64,
    uncertain: AtomicU64,
    budget_exhausted: AtomicU64,
    records_committed: AtomicU64,
    records_missed: AtomicU64,
}

impl CommitmentAccounting {
    /// Fresh accounting for `provider`, with a budget of `ceiling`.
    pub(crate) fn new(provider: ProviderId, ceiling: usize) -> Self {
        CommitmentAccounting {
            provider,
            budget: CommitmentBudget::new(ceiling),
            committed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            unavailable: AtomicU64::new(0),
            uncertain: AtomicU64::new(0),
            budget_exhausted: AtomicU64::new(0),
            records_committed: AtomicU64::new(0),
            records_missed: AtomicU64::new(0),
        }
    }

    /// The provider these counts are about.
    pub(crate) fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// The commitment budget.
    pub(crate) fn budget(&self) -> &CommitmentBudget {
        &self.budget
    }

    /// A commitment refused before its provider was asked: the budget was spent.
    pub(crate) fn note_budget_exhausted(&self) {
        self.budget_exhausted.fetch_add(1, Ordering::Relaxed);
    }

    /// One commitment attempt, counted when it settles — or as uncertain when it is dropped
    /// unsettled, which is what a cancelled or drained commitment is (W2, W7).
    pub(crate) fn attempt(&self) -> Attempt<'_> {
        Attempt {
            accounting: self,
            settled: false,
        }
    }

    /// One accounting record's fate: committed, or missed.
    pub(crate) fn note_record(&self, committed: bool) {
        let counter = if committed {
            &self.records_committed
        } else {
            &self.records_missed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// The commitment counts, merged with the observer's (`audit_sink`) into one snapshot.
    pub(crate) fn snapshot(&self) -> AccountingCounts {
        let observer = crate::audit_sink::observer_accounting::observer_counts();
        AccountingCounts {
            committed: self.committed.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            unavailable: self.unavailable.load(Ordering::Relaxed),
            uncertain: self.uncertain.load(Ordering::Relaxed),
            budget_exhausted: self.budget_exhausted.load(Ordering::Relaxed),
            ..observer
        }
    }

    /// The line printed once the run has been torn down.
    ///
    /// It says what this process observed and nothing more: a commitment the drain cut is
    /// counted UNCERTAIN, never committed and never "not executed", and the counts are a
    /// lower bound — refusals before any record existed were never counted.
    pub(crate) fn shutdown_line(&self) -> String {
        let c = self.snapshot();
        format!(
            "mcp-re-proxy: audit commitment at shutdown provider={}: committed={} \
             rejected={} unavailable={} uncertain={} budget_exhausted={} outstanding={} \
             accounting_records committed={} missed={}; observer unattributed={} dropped={} \
             dropped_unattributed={}. Counts are what this process observed (a lower bound; \
             pre-exchange refusals are not counted). A commitment cut by the drain is UNCERTAIN, \
             never reported as committed or as not executed (ADR-MCPRE-070 W7, D2).",
            self.provider,
            c.committed,
            c.rejected,
            c.unavailable,
            c.uncertain,
            c.budget_exhausted,
            self.budget.outstanding(),
            self.records_committed.load(Ordering::Relaxed),
            self.records_missed.load(Ordering::Relaxed),
            c.unattributed,
            c.dropped,
            c.dropped_unattributed,
        )
    }
}

/// One commitment attempt in flight. Dropped unsettled, it counts as uncertain.
pub(crate) struct Attempt<'a> {
    accounting: &'a CommitmentAccounting,
    settled: bool,
}

impl Attempt<'_> {
    /// Count the attempt by how it settled.
    pub(crate) fn settle<T>(mut self, result: &Result<T, CommitmentFailure>) {
        self.settled = true;
        let a = self.accounting;
        let counter = match result {
            Ok(_) => &a.committed,
            Err(CommitmentFailure::Rejected(_)) => &a.rejected,
            Err(CommitmentFailure::Unavailable) => &a.unavailable,
            Err(CommitmentFailure::Uncertain(_)) => &a.uncertain,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.accounting.uncertain.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_commitment::{RejectReason, UncertainCause};

    fn accounting() -> CommitmentAccounting {
        CommitmentAccounting::new(ProviderId::new("journal").expect("legal"), 4)
    }

    #[test]
    fn each_settled_attempt_is_counted_by_its_class() {
        let a = accounting();
        a.attempt().settle(&Ok::<(), _>(()));
        a.attempt()
            .settle(&Err::<(), _>(CommitmentFailure::Rejected(
                RejectReason::Refused,
            )));
        a.attempt()
            .settle(&Err::<(), _>(CommitmentFailure::Unavailable));
        a.attempt()
            .settle(&Err::<(), _>(CommitmentFailure::Uncertain(
                UncertainCause::TimedOut,
            )));
        a.note_budget_exhausted();
        let c = a.snapshot();
        assert_eq!(
            (
                c.committed,
                c.rejected,
                c.unavailable,
                c.uncertain,
                c.budget_exhausted
            ),
            (1, 1, 1, 1, 1)
        );
    }

    /// A cancelled or drained commitment is uncertain — never committed, never absent.
    #[test]
    fn an_attempt_dropped_unsettled_is_uncertain() {
        let a = accounting();
        drop(a.attempt());
        let c = a.snapshot();
        assert_eq!((c.committed, c.uncertain), (0, 1));
    }

    /// The report names the provider, states the cut-by-drain rule and never claims more than
    /// a lower bound.
    #[test]
    fn the_shutdown_line_states_its_limits() {
        let a = accounting();
        a.note_record(true);
        a.note_record(false);
        let line = a.shutdown_line();
        assert!(line.contains("provider=journal"), "{line}");
        assert!(
            line.contains("accounting_records committed=1 missed=1"),
            "{line}"
        );
        assert!(line.contains("outstanding=0"), "{line}");
        assert!(line.contains("UNCERTAIN"), "{line}");
        assert!(line.contains("lower bound"), "{line}");
    }
}
