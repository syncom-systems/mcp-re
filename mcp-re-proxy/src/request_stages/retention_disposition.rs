// SPDX-License-Identifier: Apache-2.0
//! The retention owner's lifecycle products, carried across the dispatch boundary
//! (ADR-MCPRE-054, #741).
//!
//! They live outside the retention module on purpose: [`crate::request_stages`] states the
//! boundary they cross, and the retention owner's statement that nothing is retained
//! ([`NothingRetained`](crate::http_profile_serve::retention::NothingRetained)) is what keeps
//! their `NotConfigured` arms from being written by anyone else.

use std::sync::Arc;

use crate::transparency::DispatchCommitted;
use crate::transparency::EvidenceRetention;
use crate::transparency::ReservedBeforeDispatch;

/// What this exchange owes the evidence store BEFORE it commits to a dispatch.
///
/// Distinct from [`RetentionDisposition`] because they are distinct facts, and the whole
/// #741 repair is that they used to be one. `Reserved` says an obligation was ACCEPTED and
/// says nothing about execution; the disposition below says the execution threshold was
/// crossed and that the crossing is durable. One value meaning both left a refused call
/// indistinguishable from one whose backend may have acted — on disk, in the exchange
/// machine, and in what the client was told.
pub(crate) enum PreDispatchRetention {
    /// This deployment retains nothing; the witness is the retention owner's statement of it.
    NotConfigured(crate::http_profile_serve::retention::NothingRetained),
    /// The obligation is durably accepted, and nothing has run. Dropping this rescinds it.
    ///
    /// The STORE travels with the reservation, so holding a `Reserved` IS holding the store
    /// that made it. Re-fetching it at each later step needed an arm for an absent one, and
    /// the only answer available there was `NotConfigured` — *this deployment retains
    /// nothing*, said about a deployment that retains and has lost its store.
    Reserved {
        store: Arc<EvidenceRetention>,
        reservation: ReservedBeforeDispatch,
    },
}

/// What this exchange owes the evidence store, as a closed set.
///
/// # Why this is not `Option<DispatchCommitted>`
///
/// Retention is optional — a deployment may run without it — so the obvious typed form is
/// an `Option`, and it is wrong. `None` would mean BOTH "this deployment retains nothing"
/// and "this deployment retains, and the record is missing", and the second is a bypassed
/// step. Keeping them in one shape is what forced the runtime guard on the completion
/// path:
///
/// ```text
/// if retention.is_some() && reservation.is_none() { internal error }
/// ```
///
/// which is a check compensating for something the type could not say (ADR-MCPRE-058
/// §9.5, §9.6). As a sum type there is no third case: the ready state PROVES
/// *retention is not configured XOR the crossing is durably recorded*, and the obligation
/// is discharged after dispatch by an exhaustive match rather than by asking whether an
/// earlier step was performed.
pub(crate) enum RetentionDisposition {
    /// This deployment retains nothing; the owner's witness keeps a configured one out of here.
    NotConfigured(crate::http_profile_serve::retention::NothingRetained),
    /// The execution threshold is durably recorded, and this exchange must complete the
    /// record before it is served. Carries the store that recorded it, for the same reason
    /// [`PreDispatchRetention::Reserved`] does.
    Committed {
        store: Arc<EvidenceRetention>,
        crossing: DispatchCommitted,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §9.6 acceptance test for the state model, stated as an assertion about the
    /// type rather than about a run.
    ///
    /// `RetentionDisposition` has exactly two cases, and the completion path matches on
    /// them exhaustively. There is no third — no `Reserved(None)`, no "configured but
    /// missing" — so the runtime guard that used to sit on the completion path has
    /// nothing left to detect.
    ///
    /// The broken implementation this catches is the one the ADR names: reaching for
    /// `Option<RetentionReservation>` inside the ready state, which reintroduces the third
    /// case and brings the guard straight back. That would not compile against this match,
    /// because `None` would have to mean one of these two arms and the compiler cannot
    /// choose.
    #[test]
    fn the_retention_obligation_has_exactly_two_cases() {
        let disposition = RetentionDisposition::NotConfigured(
            crate::http_profile_serve::retention::NothingRetained::for_a_test(),
        );
        let owed = match disposition {
            RetentionDisposition::NotConfigured(_) => false,
            RetentionDisposition::Committed { .. } => true,
        };
        assert!(
            !owed,
            "a deployment without retention owes the store nothing"
        );
    }
}
