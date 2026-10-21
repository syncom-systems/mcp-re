// SPDX-License-Identifier: Apache-2.0
//! The audit-commitment machine A (ADR-MCPRE-070 §4, D7), as a model checked against the
//! request machine R and against the types that carry it.
//!
//! Test-only, deliberately. A is a SIBLING of R, not a field of `ExchangeProgress`: the
//! frozen request region is untouched, and A's legality is already held by types —
//! `IntentDisposition::Committed` is obtainable only through G1, and the ready state cannot be
//! built without an `IntentDisposition`. A runtime copy of A beside those types would be a
//! second statement of one fact. What this module adds is the statement itself, and tests
//! that the typestate and R agree with it.
//!
//! ```text
//! [*] ──BestEffort──> NotRequired
//! [*] ──Required────> IntentPending ──witness redeemed──> IntentCommitted ──> OutcomeCommitted
//!                          │                                   └──failure──> OutcomeUncertain
//!                          ├──Rejected | Unavailable──> IntentFailed       (no dispatch)
//!                          └──timeout | cancel────────> IntentUncertain    (no dispatch)
//! ```

/// A state of one exchange's audit commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuditCommitmentState {
    /// Best-effort posture: nothing is owed.
    NotRequired,
    /// Required posture, intent not yet answered.
    IntentPending,
    /// The intent's witness was redeemed for this exchange.
    IntentCommitted,
    /// The intent was definitely not committed.
    IntentFailed,
    /// The intent may or may not be committed.
    IntentUncertain,
    /// The outcome's witness was redeemed (#1205).
    OutcomeCommitted,
    /// The outcome commit failed, timed out or was cut short (#1205).
    OutcomeUncertain,
}

/// What moves A.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuditCommitmentEvent {
    PostureBestEffort,
    PostureRequired,
    IntentRedeemed,
    IntentDefinitelyNotCommitted,
    IntentPossiblyCommitted,
    OutcomeRedeemed,
    OutcomeNotRedeemed,
}

/// A's transition relation: the next state, or `None` for an illegal step. `None` as the
/// current state is the start.
pub(super) fn transition(
    from: Option<AuditCommitmentState>,
    event: AuditCommitmentEvent,
) -> Option<AuditCommitmentState> {
    use AuditCommitmentEvent as E;
    use AuditCommitmentState as S;
    match (from, event) {
        (None, E::PostureBestEffort) => Some(S::NotRequired),
        (None, E::PostureRequired) => Some(S::IntentPending),
        (Some(S::IntentPending), E::IntentRedeemed) => Some(S::IntentCommitted),
        (Some(S::IntentPending), E::IntentDefinitelyNotCommitted) => Some(S::IntentFailed),
        (Some(S::IntentPending), E::IntentPossiblyCommitted) => Some(S::IntentUncertain),
        (Some(S::IntentCommitted), E::OutcomeRedeemed) => Some(S::OutcomeCommitted),
        (Some(S::IntentCommitted), E::OutcomeNotRedeemed) => Some(S::OutcomeUncertain),
        _ => None,
    }
}

/// Whether an exchange in `state` may cross the dispatch threshold (S1).
pub(super) fn admits_dispatch(state: AuditCommitmentState) -> bool {
    matches!(
        state,
        AuditCommitmentState::NotRequired | AuditCommitmentState::IntentCommitted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_commitment::{CommitmentFailure, RejectReason, UncertainCause};
    use crate::exchange_state::{transition as r_transition, ExchangeEvent, ExchangeState};
    use crate::request_stages::IntentDisposition;
    use AuditCommitmentState as S;

    const ALL: [S; 7] = [
        S::NotRequired,
        S::IntentPending,
        S::IntentCommitted,
        S::IntentFailed,
        S::IntentUncertain,
        S::OutcomeCommitted,
        S::OutcomeUncertain,
    ];

    const R: [ExchangeState; 23] = [
        ExchangeState::Received,
        ExchangeState::Verified,
        ExchangeState::TransportBound,
        ExchangeState::AdmissionChecked,
        ExchangeState::ContinuationPrepared,
        ExchangeState::ReplayAdmitted,
        ExchangeState::Answerable,
        ExchangeState::ContinuationRetired,
        ExchangeState::Forwarded,
        ExchangeState::InnerPlaneAccepted,
        ExchangeState::RetentionCommitted,
        ExchangeState::Dispatched,
        ExchangeState::ResponseObserved,
        ExchangeState::ResponseValidated,
        ExchangeState::ResponseClassified,
        ExchangeState::ResponseSigned,
        ExchangeState::ContinuationSettled,
        ExchangeState::Retained,
        ExchangeState::AcknowledgedNotification,
        ExchangeState::CompletedTerminal,
        ExchangeState::CompletedContinuationOpen,
        ExchangeState::RefusedBeforeDispatch,
        ExchangeState::FailedAfterDispatch,
    ];

    /// The model's reading of what the G1 types carry.
    fn of_disposition(disposition: &IntentDisposition) -> S {
        match disposition {
            IntentDisposition::NotRequired(_) => S::NotRequired,
            IntentDisposition::Committed(_) => S::IntentCommitted,
        }
    }

    /// The model's reading of a failed intent commit.
    fn of_failure(failure: &CommitmentFailure) -> S {
        let event = if failure.possibly_committed() {
            AuditCommitmentEvent::IntentPossiblyCommitted
        } else {
            AuditCommitmentEvent::IntentDefinitelyNotCommitted
        };
        transition(Some(S::IntentPending), event).expect("a failure leaves IntentPending")
    }

    #[test]
    fn machine_a_admits_dispatch_only_from_intent_committed_or_not_required() {
        let admitted: Vec<S> = ALL.into_iter().filter(|s| admits_dispatch(*s)).collect();
        assert_eq!(admitted, [S::NotRequired, S::IntentCommitted]);
        // Every reachable state that admits dispatch is reached from its posture's start by
        // a redeemed witness or by the best-effort statement, never by a failure.
        assert_eq!(
            transition(None, AuditCommitmentEvent::PostureBestEffort),
            Some(S::NotRequired)
        );
        let pending = transition(None, AuditCommitmentEvent::PostureRequired);
        assert_eq!(pending, Some(S::IntentPending));
        assert!(!admits_dispatch(S::IntentPending));
        for failure in [
            AuditCommitmentEvent::IntentDefinitelyNotCommitted,
            AuditCommitmentEvent::IntentPossiblyCommitted,
        ] {
            let failed = transition(pending, failure).expect("legal");
            assert!(!admits_dispatch(failed), "{failed:?}");
            for event in [
                AuditCommitmentEvent::IntentRedeemed,
                AuditCommitmentEvent::OutcomeRedeemed,
            ] {
                assert_eq!(
                    transition(Some(failed), event),
                    None,
                    "no way back from a failure"
                );
            }
        }
        // Past the threshold the outcome is committed or uncertain; neither re-admits a
        // dispatch, and neither is reachable without a committed intent.
        let committed = transition(pending, AuditCommitmentEvent::IntentRedeemed);
        assert_eq!(committed, Some(S::IntentCommitted));
        for (event, landed) in [
            (AuditCommitmentEvent::OutcomeRedeemed, S::OutcomeCommitted),
            (
                AuditCommitmentEvent::OutcomeNotRedeemed,
                S::OutcomeUncertain,
            ),
        ] {
            assert_eq!(transition(committed, event), Some(landed));
            assert_eq!(transition(Some(S::NotRequired), event), None);
            assert!(!admits_dispatch(landed));
        }
    }

    /// D7, composed: the dispatch edge of R is legal only from `RetentionCommitted`, and the
    /// pair crosses only where A admits it. G1 is answered while R is `InnerPlaneAccepted` —
    /// after every free pre-dispatch refusal, before the retention commit — so every A
    /// failure is a refusal in an R state where the backend cannot have run.
    #[test]
    fn machine_a_composes_with_r_only_between_inner_plane_accepted_and_retention_committed() {
        for r in R {
            for a in ALL {
                let crosses =
                    r_transition(r, ExchangeEvent::BackendDispatched).is_ok() && admits_dispatch(a);
                let expected = r == ExchangeState::RetentionCommitted
                    && matches!(a, S::NotRequired | S::IntentCommitted);
                assert_eq!(crosses, expected, "({r:?}, {a:?})");
            }
        }
        let g1 = ExchangeState::InnerPlaneAccepted;
        assert!(
            !g1.backend_may_have_executed(),
            "a G1 refusal is free of execution"
        );
        assert!(r_transition(g1, ExchangeEvent::RetentionCommitted).is_ok());
        assert!(r_transition(g1, ExchangeEvent::BackendDispatched).is_err());
    }

    /// The types and the model agree: each disposition is a state A admits dispatch from, and
    /// each failure class lands where the ADR's diagram puts it.
    #[test]
    fn the_g1_types_carry_exactly_the_states_the_model_names() {
        let not_required = IntentDisposition::NotRequired(
            crate::audit_commitment::NoCommitmentRequired::for_a_test(),
        );
        assert!(admits_dispatch(of_disposition(&not_required)));
        assert_eq!(
            of_failure(&CommitmentFailure::Rejected(RejectReason::Refused)),
            S::IntentFailed
        );
        assert_eq!(of_failure(&CommitmentFailure::Unavailable), S::IntentFailed);
        for cause in [UncertainCause::TimedOut, UncertainCause::Cancelled] {
            assert_eq!(
                of_failure(&CommitmentFailure::Uncertain(cause)),
                S::IntentUncertain
            );
        }
    }
}
