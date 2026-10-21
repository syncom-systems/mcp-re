// SPDX-License-Identifier: Apache-2.0
//! The bounded aggregate accounting record (ADR-MCPRE-070 D2, Q3).
//!
//! Individual unauthenticated and pre-exchange attempts stay best-effort (D2). What a
//! deployment under the required posture commits about them is one aggregate record per
//! interval of its run: `mcp-re.audit.accounting`, the fifth audit category (vocabulary
//! revision 3). It carries no actor, because it is about no one, and no `reason`, because it
//! is not a verdict. It is never offered to the observer, so the best-effort stream keeps its
//! v0.18.1 contract.
//!
//! # What the numbers mean
//!
//! * **Cumulative.** Every count runs from the start of the run, not from the start of the
//!   interval. A record that could not be committed therefore loses no count: the next
//!   committed record carries it. What a missing record loses is resolution in time.
//! * **Missing intervals are stated.** `missed` is how many earlier intervals of this run
//!   produced no committed record — an outage, an exhausted budget, a rejection, or an
//!   uncertain answer (which may or may not have been committed, and is counted as missed
//!   because the run cannot know). A reader that sees interval `n` with `missed = 0` holds
//!   every earlier record; one that sees `missed > 0` knows exactly how many it does not.
//! * **Lost and unknown, separately.** `dropped` and `dropped_unattributed` are observer
//!   records this process KNOWS it lost; `uncertain` is commitments whose outcome is unknown.
//! * **Never exhaustive.** `coverage` is always [`COVERAGE`]: the counts are what this process
//!   observed, a lower bound. Refusals before any record exists (TLS, per-core shedding,
//!   malformed or oversized requests) are not counted at all, and a record cut by a drain or
//!   a crash is absent rather than zero. Under a total provider outage or adversarial
//!   saturation no record claims more than it saw (D2).

use mcp_re_core::audit::event_type;

use super::envelope::{process_allocator, CanonicalEvent, EventScope};
use super::text::AuditField;
use super::EventIdentityFailure;

/// The record's own statement that its counts are a lower bound, never exhaustive.
pub(crate) const COVERAGE: &str = "observed-lower-bound";

/// What one process counted since its run started. Plain data, filled by the owners of
/// each count; this type decides only how they are written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AccountingCounts {
    /// Records with no verifier-resolved actor offered to the observer.
    pub(crate) unattributed: u64,
    /// Observer records dropped, of every attribution.
    pub(crate) dropped: u64,
    /// Observer records with no actor that were dropped.
    pub(crate) dropped_unattributed: u64,
    /// Commitments the provider acknowledged and the owner bound.
    pub(crate) committed: u64,
    /// Commitments the provider refused.
    pub(crate) rejected: u64,
    /// Commitments refused as unavailable: the provider's own answer.
    pub(crate) unavailable: u64,
    /// Commitments whose outcome is unknown.
    pub(crate) uncertain: u64,
    /// Commitments refused before the provider was asked, because the budget was spent.
    pub(crate) budget_exhausted: u64,
}

/// One interval of one run's accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AccountingRecord {
    /// The interval's index within the run, from zero.
    pub(crate) interval: u64,
    /// When the interval opened and closed, in Unix seconds.
    pub(crate) from_unix: i64,
    pub(crate) to_unix: i64,
    /// Earlier intervals of this run whose record was not committed.
    pub(crate) missed: u64,
    /// The cumulative counts at the interval's close.
    pub(crate) counts: AccountingCounts,
}

/// A count as the canonical encoding's signed number. A count past `i64::MAX` is written as
/// `i64::MAX`, which is still a lower bound and never a wrapped one.
fn number(count: u64) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

impl AccountingRecord {
    /// The record's fields, each classified by its owner: fourteen, in this order. Its own
    /// arm of the canonical schema (`canonical.rs`).
    pub(in crate::audit_record) fn audit_fields(&self) -> [AuditField<'static>; 14] {
        let c = &self.counts;
        [
            AuditField::token("event", event_type::AUDIT_ACCOUNTING),
            AuditField::number("interval", number(self.interval)),
            AuditField::number("from", self.from_unix),
            AuditField::number("to", self.to_unix),
            AuditField::number("missed", number(self.missed)),
            AuditField::number("unattributed", number(c.unattributed)),
            AuditField::number("dropped", number(c.dropped)),
            AuditField::number("dropped_unattributed", number(c.dropped_unattributed)),
            AuditField::number("committed", number(c.committed)),
            AuditField::number("rejected", number(c.rejected)),
            AuditField::number("unavailable", number(c.unavailable)),
            AuditField::number("uncertain", number(c.uncertain)),
            AuditField::number("budget_exhausted", number(c.budget_exhausted)),
            AuditField::token("coverage", COVERAGE),
        ]
    }

    /// Produce this record as the process's next event, scoped to the run.
    ///
    /// Numbered by the same allocator as every other event, so its identity is unique in
    /// the run and the run it counts is the run its identity names.
    pub(crate) fn produce(&self) -> Result<CanonicalEvent, EventIdentityFailure> {
        process_allocator().and_then(|allocator| {
            CanonicalEvent::produce(allocator, EventScope::of_run, &self.audit_fields())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_record::text::AuditValue;

    fn record() -> AccountingRecord {
        AccountingRecord {
            interval: 2,
            from_unix: 120,
            to_unix: 180,
            missed: 1,
            counts: AccountingCounts {
                unattributed: 9,
                dropped: 3,
                dropped_unattributed: 2,
                committed: 40,
                rejected: 1,
                unavailable: 4,
                uncertain: 1,
                budget_exhausted: 5,
            },
        }
    }

    /// No actor and no reason: the record is about no one and decides nothing (Q3).
    #[test]
    fn the_record_names_no_actor_and_no_reason() {
        let names: Vec<&str> = record().audit_fields().iter().map(|f| f.name).collect();
        assert!(!names.contains(&"actor"));
        assert!(!names.contains(&"reason"));
        assert!(!names.contains(&"decision"));
        assert_eq!(names.first(), Some(&"event"));
    }

    /// The record never claims exhaustiveness, whatever it counted.
    #[test]
    fn the_coverage_is_always_a_lower_bound() {
        for counts in [AccountingCounts::default(), record().counts] {
            let r = AccountingRecord { counts, ..record() };
            let coverage = r.audit_fields().last().map(|f| f.value.clone());
            assert_eq!(coverage, Some(AuditValue::Token(COVERAGE)));
        }
        assert!(!COVERAGE.contains("exhaustive"));
    }

    /// A count past `i64::MAX` is written as a lower bound, never wrapped negative.
    #[test]
    fn an_unrepresentable_count_saturates_rather_than_wraps() {
        assert_eq!(number(u64::MAX), i64::MAX);
        assert_eq!(number(7), 7);
    }

    /// The record is produced in the run scope, belonging to no exchange.
    #[test]
    fn the_record_belongs_to_the_run_and_no_exchange() {
        crate::audit_record::open_process_run().expect("the OS CSPRNG yields a run");
        let event = record().produce().expect("produced");
        assert_eq!(event.scope(), EventScope::Run);
        assert_eq!(event.exchange_coordinate(), None);
    }
}
