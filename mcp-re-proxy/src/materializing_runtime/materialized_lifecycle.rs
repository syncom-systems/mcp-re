// SPDX-License-Identifier: Apache-2.0
//! The materialization-phase transitions of the lifecycle, each applied where its fact
//! is established, and the lifecycle of a runtime whose every required resource is owned.
//!
//! [`started`] records validation, planning and the start of materialization from the
//! proof the composition root holds; [`failed`] records a failed materialization after the
//! partial reclaim; [`MaterializedLifecycle::reached`] is the sole producer of
//! `MaterializationSucceeded`, called by
//! [`MaterializingRuntime::finish`](super::MaterializingRuntime::finish) once the last
//! required resource is taken (ADR-MCPRE-057 §9). All three are `pub(super)`, so no code
//! outside `materializing_runtime` applies these events, and
//! [`MaterializedRuntime::new`](crate::materialized_runtime::MaterializedRuntime::new)
//! takes this type rather than a bare `RuntimeLifecycle`. Possession is the proof: a
//! `MaterializedRuntime` cannot be assembled around a lifecycle that skipped validation,
//! planning or materialization, because no such value of this type exists.
//!
//! Sealed by module privacy, the lever that binds inside this crate: the field is private
//! to this module, the producer is `pub(super)`, and nothing derives a constructor.
//! `structural://proxy/materialized_lifecycle/sole_producer` (probes S55 and S56) compiles
//! the two forgeries and requires the compiler to refuse them.

use crate::config_state::validation::ValidatedDeployment;
use crate::runtime_state::InvalidTransition;
use crate::runtime_state::RuntimeEvent;
use crate::runtime_state::RuntimeLifecycle;
use crate::runtime_state::RuntimeState;

/// A lifecycle at `Materializing`, from the proof the root holds.
///
/// Holding a `ValidatedDeployment` IS the proof of `ValidationSucceeded`, and of
/// `PlanBuilt`: every plan is a pure, total projection of it (`*Plan::from_validated`).
/// Some pure planning still runs inside `Materializing`, which the relation tolerates
/// (ADR-MCPRE-058 §17A step 5 is where the two stop interleaving).
pub(super) fn started(
    _deployment: &ValidatedDeployment,
) -> Result<RuntimeLifecycle, InvalidTransition> {
    let mut lifecycle = RuntimeLifecycle::new();
    lifecycle.apply(RuntimeEvent::ValidationSucceeded)?;
    lifecycle.apply(RuntimeEvent::PlanBuilt)?;
    lifecycle.apply(RuntimeEvent::MaterializationStarted)?;
    Ok(lifecycle)
}

/// Record a failed materialization, once the partial resources have been reclaimed.
///
/// `Materializing` always has this transition, so a refusal would mean the relation
/// changed underneath us. Ignored rather than panicking: this runs on an unwind path,
/// where panicking again aborts the process and loses the original error the operator
/// needs.
pub(super) fn failed(mut lifecycle: RuntimeLifecycle) -> RuntimeState {
    let _ = lifecycle.apply(RuntimeEvent::MaterializationFailed);
    lifecycle.state()
}

/// A `RuntimeLifecycle` that reached `Materialized` over a complete resource graph.
pub(crate) struct MaterializedLifecycle {
    lifecycle: RuntimeLifecycle,
}

impl MaterializedLifecycle {
    /// The only producer, and the only site that applies `MaterializationSucceeded`:
    /// `finish` calls it once every required resource has been taken.
    pub(super) fn reached(mut lifecycle: RuntimeLifecycle) -> Result<Self, InvalidTransition> {
        lifecycle.apply(RuntimeEvent::MaterializationSucceeded)?;
        Ok(Self { lifecycle })
    }

    /// Spend the certificate for the lifecycle it covers.
    pub(crate) fn into_lifecycle(self) -> RuntimeLifecycle {
        self.lifecycle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deployment that passed the legality boundary — the proof `started` takes.
    fn deployment() -> ValidatedDeployment {
        ValidatedDeployment::try_from(crate::config_state::test_support::legal_config())
            .expect("the fixture validates")
    }

    /// A lifecycle that has legally reached `Materializing`, where `reached` takes it.
    fn materializing() -> RuntimeLifecycle {
        started(&deployment()).expect("the startup path is legal")
    }

    /// The proof the root holds is spent for a lifecycle at `Materializing`, and nowhere
    /// else: validation, planning and the start are recorded as one act.
    #[test]
    fn started_yields_a_lifecycle_at_materializing() {
        assert_eq!(materializing().state(), RuntimeState::Materializing);
    }

    /// A failed materialization ends at `FailedToStart`, the terminal state distinct from a
    /// served shutdown; `failed` consumes the lifecycle, so nothing can advance it past that.
    #[test]
    fn failed_ends_the_lifecycle_at_failed_to_start() {
        assert_eq!(failed(materializing()), RuntimeState::FailedToStart);
    }

    /// The producer applies the transition it certifies, so the lifecycle it hands back
    /// is at `Materialized` and nowhere else.
    #[test]
    fn reached_applies_materialization_succeeded_and_yields_materialized() {
        let certified = MaterializedLifecycle::reached(materializing())
            .expect("MaterializationSucceeded is legal from Materializing");
        assert_eq!(
            certified.into_lifecycle().state(),
            RuntimeState::Materialized
        );
    }

    /// A lifecycle that never entered `Materializing` cannot be certified: the relation
    /// refuses, and the refusal names the state and the event.
    #[test]
    fn reached_refuses_a_lifecycle_that_never_started_materializing() {
        let err = MaterializedLifecycle::reached(RuntimeLifecycle::new())
            .err()
            .expect("MaterializationSucceeded is illegal from Configured");
        assert_eq!(err.state, RuntimeState::Configured);
        assert_eq!(err.event, RuntimeEvent::MaterializationSucceeded);
    }
}
