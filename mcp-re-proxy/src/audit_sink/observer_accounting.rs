// SPDX-License-Identifier: Apache-2.0
//! The observer's cumulative counts, for the required posture's accounting record
//! (ADR-MCPRE-070 §7.2, D2, Q3).
//!
//! The writer's drop counter is a REPORT counter: it is drained each time the writer states
//! its drops, so it cannot say how many were lost over a run. These are never reset. They
//! count only what reached [`super::StderrAuditSink::record`]: a refusal answered before any
//! record existed is not here, which is why the record that carries them never claims to be
//! exhaustive.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::audit_record::AccountingCounts;

/// Records with no verifier-resolved actor offered to the stderr observer.
static UNATTRIBUTED_OFFERED: AtomicU64 = AtomicU64::new(0);
/// Records the stderr observer dropped, of every attribution.
static DROPPED: AtomicU64 = AtomicU64::new(0);
/// Records with no actor that the stderr observer dropped.
static DROPPED_UNATTRIBUTED: AtomicU64 = AtomicU64::new(0);

/// Count one offered record by its attribution and whether the queue admitted it.
pub(super) fn count_offer(attributed: bool, admitted: bool) {
    if !attributed {
        UNATTRIBUTED_OFFERED.fetch_add(1, Ordering::Relaxed);
    }
    if !admitted {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        if !attributed {
            DROPPED_UNATTRIBUTED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The observer's cumulative counts; every commitment count is zero here.
pub(crate) fn observer_counts() -> AccountingCounts {
    AccountingCounts {
        unattributed: UNATTRIBUTED_OFFERED.load(Ordering::Relaxed),
        dropped: DROPPED.load(Ordering::Relaxed),
        dropped_unattributed: DROPPED_UNATTRIBUTED.load(Ordering::Relaxed),
        ..AccountingCounts::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts only grow, each by its own class; a dropped unattributed record is counted
    /// as offered, as dropped, and as dropped unattributed.
    #[test]
    fn each_class_is_counted_and_never_reset() {
        let before = observer_counts();
        count_offer(true, true);
        count_offer(false, true);
        count_offer(false, false);
        count_offer(true, false);
        let after = observer_counts();
        assert!(after.unattributed >= before.unattributed + 2);
        assert!(after.dropped >= before.dropped + 2);
        assert!(after.dropped_unattributed > before.dropped_unattributed);
        assert_eq!(after.committed, 0);
    }
}
