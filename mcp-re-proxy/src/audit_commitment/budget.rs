// SPDX-License-Identifier: Apache-2.0
//! The commitment path's own bounded in-flight budget (ADR-MCPRE-070 §7.4).

use tokio::sync::{Semaphore, SemaphorePermit};

/// How many commitments may be in flight at once.
///
/// The magnitude of retention's `MAX_RESERVATIONS` (`transparency/durability_bounds.rs`),
/// and independent of it: the two budgets have two owners, are each try-acquired and
/// released on drop, so neither can starve or deadlock the other (§7.5). A constant, not a
/// flag: nothing has been measured that would size an operator knob.
pub(crate) const BUDGET_CEILING: usize = 1024;

/// The commitment budget: permits that are TRIED, never waited for.
///
/// A commitment that finds the budget spent is refused before its provider is asked, as
/// `Unavailable`, and the exchange is refused before dispatch with the typed, retry-safe 503
/// (§7.3, D12) — the same shape as a provider outage. It never degrades to observation.
///
/// Separate from the observer's queue and ceiling: an unauthenticated flood reaches only
/// the observer (it never passes G1), so it cannot spend a permit, and a stalled provider
/// that holds every permit cannot cost the observer a slot (§7.4).
#[derive(Debug)]
pub(crate) struct CommitmentBudget {
    permits: Semaphore,
    ceiling: usize,
}

impl CommitmentBudget {
    /// A budget of `ceiling` permits.
    pub(crate) fn new(ceiling: usize) -> Self {
        CommitmentBudget {
            permits: Semaphore::new(ceiling),
            ceiling,
        }
    }

    /// One permit, released when it is dropped — including when the commitment holding it is
    /// cancelled — or `None` at once when every permit is held. Never waits.
    pub(crate) fn try_acquire(&self) -> Option<SemaphorePermit<'_>> {
        self.permits.try_acquire().ok()
    }

    /// How many permits are held now.
    pub(crate) fn outstanding(&self) -> usize {
        self.ceiling
            .saturating_sub(self.permits.available_permits())
    }

    /// How many permits there are.
    pub(crate) fn ceiling(&self) -> usize {
        self.ceiling
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustion answers at once rather than waiting, and a dropped permit is returned.
    #[test]
    fn a_spent_budget_refuses_at_once_and_a_dropped_permit_returns() {
        let budget = CommitmentBudget::new(2);
        let first = budget.try_acquire().expect("a permit");
        let second = budget.try_acquire().expect("a permit");
        assert_eq!(budget.outstanding(), 2);
        assert!(budget.try_acquire().is_none(), "never waits for a permit");
        drop(first);
        assert_eq!(budget.outstanding(), 1);
        assert!(budget.try_acquire().is_some());
        drop(second);
        assert_eq!(budget.outstanding(), 0);
    }

    /// A permit held by a cancelled future is returned with it.
    #[tokio::test]
    async fn a_cancelled_holder_returns_its_permit() {
        let budget = CommitmentBudget::new(1);
        let held = async {
            let _permit = budget.try_acquire().expect("a permit");
            std::future::pending::<()>().await;
        };
        let cut = tokio::time::timeout(std::time::Duration::from_millis(5), held).await;
        assert!(cut.is_err());
        assert_eq!(budget.outstanding(), 0);
        assert_eq!(budget.ceiling(), 1);
    }
}
