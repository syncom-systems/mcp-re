// SPDX-License-Identifier: Apache-2.0
//! The accounting record's cadence: one bounded commitment per interval of the run
//! (ADR-MCPRE-070 D2, Q3).
//!
//! The record is what the required posture permits (D2): one at a time, each under the
//! commitment bound and the same try-acquired budget as an exchange's commitments, so it
//! can neither queue behind itself nor hold more than one permit. Nothing waits on it: a
//! failure is counted as a missed interval and stated in the next record, whose cumulative
//! counts lose nothing but resolution in time. The final, partial interval of a run is not
//! committed — a drain adds no provider I/O, so the deployment's drain budget is unchanged
//! — and the shutdown report states that interval's counts instead.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::audit_record::AccountingRecord;

use super::{Accounting, CommitmentBound, EstablishedProvider};

/// How long one accounting interval lasts.
pub(crate) const ACCOUNTING_INTERVAL: Duration = Duration::from_secs(60);

/// Where the run's accounting stands between records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cadence {
    interval: u64,
    from_unix: i64,
    missed: u64,
}

impl Cadence {
    /// The first interval, opened at `from_unix`.
    pub(crate) fn opened_at(from_unix: i64) -> Self {
        Cadence {
            interval: 0,
            from_unix,
            missed: 0,
        }
    }

    /// Close the current interval at `to_unix`: produce its record, commit it to
    /// `provider` within `bound`, and open the next. Answers whether it was committed.
    pub(crate) async fn close(
        &mut self,
        provider: &Arc<EstablishedProvider>,
        bound: CommitmentBound,
        to_unix: i64,
    ) -> bool {
        let record = AccountingRecord {
            interval: self.interval,
            from_unix: self.from_unix,
            to_unix,
            missed: self.missed,
            counts: provider.accounting().snapshot(),
        };
        let committed = commit_record(provider, bound, &record).await;
        provider.accounting().note_record(committed);
        if !committed {
            self.missed = self.missed.saturating_add(1);
        }
        self.interval = self.interval.saturating_add(1);
        self.from_unix = to_unix;
        committed
    }
}

/// Produce `record`, commit it, and redeem the witness against it: `true` only when all
/// three held. Every failure is one answer — a missed interval — because nothing waits on it.
async fn commit_record(
    provider: &Arc<EstablishedProvider>,
    bound: CommitmentBound,
    record: &AccountingRecord,
) -> bool {
    let Ok(event) = record.produce() else {
        return false;
    };
    let Ok(witness) = provider.commit::<Accounting>(&event, bound).await else {
        return false;
    };
    witness.redeem(&event, provider).is_ok()
}

/// The wall clock in Unix seconds; a clock before the epoch reads as zero.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Commit one record per `every`, for as long as the runtime it is spawned on lives. The
/// control runtime is reclaimed after the proxy (ADR-MCPRE-056 §10), and dropping this
/// future there cuts at most one in-flight commitment, counted uncertain.
pub(crate) async fn run(
    provider: Arc<EstablishedProvider>,
    bound: CommitmentBound,
    every: Duration,
) {
    let mut cadence = Cadence::opened_at(now_unix());
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick completes at once; the first interval closes one period later.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        cadence.close(&provider, bound, now_unix()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_commitment::reference::{ReferenceAuthority, Step};
    use crate::audit_commitment::DurabilityTier;

    fn provider(
        steps: impl IntoIterator<Item = Step>,
    ) -> (Arc<ReferenceAuthority>, Arc<EstablishedProvider>) {
        crate::audit_record::open_process_run().expect("the OS CSPRNG yields a run");
        let authority = Arc::new(
            ReferenceAuthority::new(DurabilityTier::SurvivesProxyProcessLoss).scripted(steps),
        );
        (
            authority.clone(),
            EstablishedProvider::eligible_for_test(authority),
        )
    }

    fn bound() -> CommitmentBound {
        CommitmentBound::new(Duration::from_millis(50)).expect("legal bound")
    }

    /// Each interval's record is committed in the run scope; a failure is a missed interval
    /// the next record states, and the interval index advances either way.
    #[tokio::test]
    async fn a_failed_record_is_a_missed_interval_the_next_one_states() {
        let (authority, provider) = provider([Step::Unavailable, Step::Commit]);
        let mut cadence = Cadence::opened_at(100);
        assert!(!cadence.close(&provider, bound(), 160).await);
        assert_eq!(
            cadence,
            Cadence {
                interval: 1,
                from_unix: 160,
                missed: 1
            }
        );
        assert!(cadence.close(&provider, bound(), 220).await);
        let journaled = authority.journaled();
        assert_eq!(journaled.len(), 1, "only the second record was committed");
        assert_eq!(journaled[0].1, None, "the record belongs to no exchange");
        assert_eq!(
            cadence.missed, 1,
            "a later success does not erase a missed interval"
        );
    }

    /// A spent budget makes the record a missed interval; it does not wait for a permit.
    #[tokio::test]
    async fn a_spent_budget_is_a_missed_interval_not_a_wait() {
        let (authority, provider) = provider([]);
        let permits: Vec<_> =
            std::iter::from_fn(|| provider.accounting().budget().try_acquire()).collect();
        assert!(!permits.is_empty());
        let mut cadence = Cadence::opened_at(0);
        assert!(!cadence.close(&provider, bound(), 60).await);
        assert_eq!(authority.requests(), 0);
        assert_eq!(provider.accounting().snapshot().budget_exhausted, 1);
    }

    /// A provider that never answers costs one bound per interval, and the next still runs.
    #[tokio::test]
    async fn a_hanging_provider_is_bounded_and_missed() {
        let (_, provider) = provider([Step::Hang, Step::Commit]);
        let mut cadence = Cadence::opened_at(0);
        let first = tokio::time::timeout(
            Duration::from_secs(5),
            cadence.close(&provider, bound(), 60),
        );
        assert!(!first.await.expect("bounded"));
        assert!(cadence.close(&provider, bound(), 120).await);
        assert_eq!(provider.accounting().snapshot().uncertain, 1);
    }
}
