// SPDX-License-Identifier: Apache-2.0
//! The borrowed view an enforcing admission state is read through, and the budgets it
//! projects for the components that apply the gate.

use super::{AdmissionAvailability, AdmissionPosture, AdmissionRecordCurrentness, ValidatedGate};
use mcp_re_core::{MaxClockSkew, VerificationKey};
use mcp_re_http_profile::authoritative_admission::record::AdmissionStateCurrentness;
use mcp_re_http_profile::AdmissionPolicy;

/// An enforcing deployment's gate inputs, as one indivisible value.
///
/// Borrowed from the state, so it is a way to READ an admission posture and not a way to
/// assemble one. The posture and the authority it applies are handed over together because
/// they were validated together; nothing holding this can re-pair them. Only the admission
/// machine builds one, from its own validated gate.
#[derive(Debug, Clone, Copy)]
pub struct EnforcedAdmission<'a> {
    posture: AdmissionPosture,
    gate: &'a ValidatedGate,
}

impl<'a> EnforcedAdmission<'a> {
    /// The view of `gate`, applied at `posture`.
    pub(super) fn of(posture: AdmissionPosture, gate: &'a ValidatedGate) -> Self {
        EnforcedAdmission { posture, gate }
    }

    /// How strictly the gate is applied.
    pub fn posture(&self) -> AdmissionPosture {
        self.posture
    }

    /// The key id an assertion must present for its issuer to be recognised.
    pub fn authority_kid(&self) -> &'a str {
        &self.gate.authority_kid
    }

    /// The decoded key that verifies it.
    pub fn authority(&self) -> &'a VerificationKey {
        &self.gate.authority
    }

    /// The shared authoritative record currency is compared against.
    pub fn record_store(&self) -> &'a str {
        self.gate.record_store.locator()
    }

    /// What this deployment does when that record cannot be reached.
    pub fn availability(&self) -> AdmissionAvailability {
        self.gate.availability
    }

    /// How current a record read from that store must be to be acted on.
    pub fn record_currentness(&self) -> AdmissionRecordCurrentness {
        self.gate.currentness
    }

    /// The PEP's §5.2 budget under this gate, with `max_clock_skew` the freshness owner's.
    ///
    /// The two degraded fields are one projection of [`AdmissionAvailability`], never two
    /// settings to combine. N is the profile's budget, [`AdmissionPolicy::default`]'s, which
    /// no deployment states. The saturation cannot fire: P was narrowed from a positive `i64`.
    pub fn enforcer_policy(&self, max_clock_skew: MaxClockSkew) -> AdmissionPolicy {
        let (allow_degraded_mode, degraded_propagation_bound) = match self.gate.availability {
            AdmissionAvailability::FailClosed => (false, 0),
            AdmissionAvailability::BoundedDegraded { bound_secs } => {
                (true, i64::try_from(bound_secs.get()).unwrap_or(i64::MAX))
            }
        };
        AdmissionPolicy {
            max_clock_skew: max_clock_skew.secs(),
            degraded_propagation_bound,
            allow_degraded_mode,
            ..AdmissionPolicy::default()
        }
    }

    /// The record verifier's currentness budget under this gate, with `max_clock_skew` the
    /// freshness owner's — the same tolerance [`enforcer_policy`](Self::enforcer_policy)
    /// hands the PEP, so the assertion and the authoritative record are judged under one
    /// skew.
    pub fn record_verifier_currentness(
        &self,
        max_clock_skew: MaxClockSkew,
    ) -> AdmissionStateCurrentness {
        AdmissionStateCurrentness {
            max_record_age: self.gate.currentness.max_age_secs(),
            max_clock_skew: max_clock_skew.secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{classify_and_validate, AdmissionState};
    use crate::deployment_request::{AdmissionAvailabilityRequest, AdmissionRequest};
    use std::num::NonZeroU64;

    /// An enforcing state whose gate answers an unreachable authority with `availability`.
    fn enforcing(availability: AdmissionAvailabilityRequest) -> AdmissionState {
        let mut config = crate::config_state::test_support::enforcing_admission_config();
        let AdmissionRequest::Required(gate) = &mut config.admission else {
            panic!("the fixture enforces admission");
        };
        gate.availability = availability;
        classify_and_validate(&config)
            .0
            .expect("a complete admission configuration names a state")
    }

    fn skew(secs: i64) -> mcp_re_core::MaxClockSkew {
        mcp_re_core::MaxClockSkew::new(secs).expect("within the ceiling")
    }

    /// The projected budget for a gate whose authority, unreachable, fails closed: no
    /// degraded window, the freshness owner's skew, and the profile's N.
    #[test]
    fn a_fail_closed_gate_projects_no_degraded_window() {
        let state = enforcing(AdmissionAvailabilityRequest::FailClosed);
        let policy = state
            .enforced()
            .expect("an enforcing state")
            .enforcer_policy(skew(7));
        assert!(!policy.allow_degraded_mode);
        assert_eq!(policy.degraded_propagation_bound, 0);
        assert_eq!(policy.max_clock_skew, 7);
        assert_eq!(
            policy.max_assertion_age,
            mcp_re_http_profile::AdmissionPolicy::default().max_assertion_age
        );
    }

    /// A bounded-degraded gate projects its P and the opt-in together, as one cell.
    #[test]
    fn a_bounded_degraded_gate_projects_its_window_and_the_opt_in() {
        let state = enforcing(AdmissionAvailabilityRequest::Degraded {
            bound_secs: NonZeroU64::new(90).expect("90 is not zero"),
        });
        let policy = state
            .enforced()
            .expect("an enforcing state")
            .enforcer_policy(skew(5));
        assert!(policy.allow_degraded_mode);
        assert_eq!(policy.degraded_propagation_bound, 90);
        assert_eq!(policy.max_clock_skew, 5);
    }

    /// The record verifier is handed the gate's own record age and the skew the PEP gets.
    #[test]
    fn the_record_verifier_judges_under_the_gates_age_and_the_peps_skew() {
        let state = enforcing(AdmissionAvailabilityRequest::FailClosed);
        let gate = state.enforced().expect("an enforcing state");
        let currentness = gate.record_verifier_currentness(skew(7));
        assert_eq!(
            currentness.max_record_age,
            gate.record_currentness().max_age_secs()
        );
        assert_eq!(currentness.max_record_age, 60, "the fixture's record age");
        assert_eq!(
            currentness.max_clock_skew,
            gate.enforcer_policy(skew(7)).max_clock_skew
        );
    }
}
